const express=require("express");
const path=require("path");
const fs=require("fs");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");

const app=express();
const PORT=process.env.PORT||3000;
const JWT_SECRET=process.env.JWT_SECRET||"RUTAAERO_DEV_CAMBIAR_EN_PRODUCCION";
const DB=path.join(__dirname,"data.json");

function load(){
  if(!fs.existsSync(DB)) fs.writeFileSync(DB,JSON.stringify({
    users:[],vehicles:[],routes:[],pickupPoints:[],bookings:[],tokenTransactions:[]
  },null,2));
  return JSON.parse(fs.readFileSync(DB,"utf8"));
}
function save(db){fs.writeFileSync(DB,JSON.stringify(db,null,2))}
function id(){return Date.now().toString(36)+Math.random().toString(36).slice(2,8)}
function auth(req,res,next){
  const h=req.headers.authorization||"";
  if(!h.startsWith("Bearer ")) return res.status(401).json({error:"No autenticado"});
  try{req.user=jwt.verify(h.slice(7),JWT_SECRET);next()}
  catch{return res.status(401).json({error:"Token no válido"})}
}
function safeUser(u){return {id:u.id,name:u.name,email:u.email,role:u.role,tokens:u.tokens}}
app.use(express.json());
app.use(express.static(path.join(__dirname,"public")));

app.post("/api/auth/register",(req,res)=>{
  const {name,email,password,role}=req.body;
  if(!name||!email||!password||!["conductor","pasajero"].includes(role))
    return res.status(400).json({error:"Datos incompletos"});
  if(password.length<6)return res.status(400).json({error:"La contraseña debe tener 6 caracteres o más"});
  const db=load(),e=email.toLowerCase().trim();
  if(db.users.some(u=>u.email===e))return res.status(409).json({error:"El email ya está registrado"});
  const u={id:id(),name:name.trim(),email:e,passwordHash:bcrypt.hashSync(password,10),role,tokens:10,createdAt:new Date().toISOString()};
  db.users.push(u);db.tokenTransactions.push({id:id(),userId:u.id,amount:10,reason:"Bono inicial",createdAt:new Date().toISOString()});save(db);
  const token=jwt.sign({id:u.id,role:u.role},JWT_SECRET,{expiresIn:"7d"});
  res.status(201).json({token,user:safeUser(u)});
});
app.post("/api/auth/login",(req,res)=>{
  const db=load(),e=String(req.body.email||"").toLowerCase().trim(),u=db.users.find(x=>x.email===e);
  if(!u||!bcrypt.compareSync(req.body.password||"",u.passwordHash))return res.status(401).json({error:"Email o contraseña incorrectos"});
  const token=jwt.sign({id:u.id,role:u.role},JWT_SECRET,{expiresIn:"7d"});
  res.json({token,user:safeUser(u)});
});
app.get("/api/me",auth,(req,res)=>{
  const u=load().users.find(x=>x.id===req.user.id);
  if(!u)return res.status(404).json({error:"Usuario no encontrado"});
  res.json(safeUser(u));
});
app.put("/api/me",auth,(req,res)=>{
  const db=load(),u=db.users.find(x=>x.id===req.user.id);
  if(req.body.name)u.name=String(req.body.name).trim();
  if(["conductor","pasajero"].includes(req.body.role))u.role=req.body.role;
  save(db);res.json(safeUser(u));
});
app.get("/api/vehicles",auth,(req,res)=>res.json(load().vehicles.filter(v=>v.userId===req.user.id)));
app.post("/api/vehicles",auth,(req,res)=>{
  if(req.user.role!=="conductor")return res.status(403).json({error:"Solo un conductor puede registrar vehículos"});
  const {brand,model,plate,seats}=req.body,n=Number(seats);
  if(!brand||!model||!plate||!Number.isInteger(n)||n<1||n>9)return res.status(400).json({error:"Datos del vehículo no válidos"});
  const db=load(),p=String(plate).toUpperCase().trim();
  if(db.vehicles.some(v=>v.plate===p))return res.status(409).json({error:"La matrícula ya existe"});
  const v={id:id(),userId:req.user.id,brand,model,plate:p,seats:n};db.vehicles.push(v);save(db);res.status(201).json(v);
});

app.delete("/api/vehicles/:id",auth,(req,res)=>{
  const db=load();
  const vehicle=db.vehicles.find(v=>v.id===req.params.id && v.userId===req.user.id);
  if(!vehicle)return res.status(404).json({error:"Vehículo no encontrado"});
  const hasRoutes=db.routes.some(r=>r.vehicleId===vehicle.id);
  if(hasRoutes)return res.status(400).json({error:"No puedes eliminar un vehículo que ya tiene rutas. Elimina o finaliza primero esas rutas."});
  db.vehicles=db.vehicles.filter(v=>v.id!==vehicle.id);
  save(db);
  res.json({ok:true});
});


app.delete("/api/routes/:id",auth,(req,res)=>{
  const db=load();
  const route=db.routes.find(r=>r.id===req.params.id && r.driverId===req.user.id);
  if(!route)return res.status(404).json({error:"Ruta no encontrada"});

  const bookings=db.bookings.filter(b=>b.routeId===route.id);
  if(bookings.length>0){
    return res.status(400).json({
      error:"Esta ruta tiene reservas. No se puede eliminar; primero debes cancelar o gestionar las reservas."
    });
  }

  db.pickupPoints=db.pickupPoints.filter(p=>p.routeId!==route.id);
  db.routes=db.routes.filter(r=>r.id!==route.id);
  save(db);
  res.json({ok:true});
});

app.post("/api/routes",auth,(req,res)=>{
  if(req.user.role!=="conductor")
    return res.status(403).json({error:"Solo un conductor puede crear rutas"});

  const db=load();
  const vehicleId=String(req.body.vehicleId||"").trim();
  const origin=String(req.body.origin||"").trim();
  const destination=String(req.body.destination||"").trim();
  const departureTime=String(req.body.departureTime||"").trim();
  const n=parseInt(req.body.availableSeats,10);

  const v=db.vehicles.find(x=>String(x.id)===vehicleId && x.userId===req.user.id);

  if(!v)
    return res.status(400).json({error:"El vehículo seleccionado no existe. Guarda el vehículo y vuelve a seleccionarlo."});
  if(!origin)
    return res.status(400).json({error:"Falta el origen de la ruta."});
  if(!destination)
    return res.status(400).json({error:"Falta el destino de la ruta."});
  if(!departureTime)
    return res.status(400).json({error:"Falta la fecha y hora de salida."});
  if(!Number.isFinite(n)||n<1)
    return res.status(400).json({error:"Las plazas disponibles deben ser un número mayor que 0."});
  if(n>Number(v.seats))
    return res.status(400).json({error:"No puedes ofrecer más plazas que las plazas del vehículo ("+v.seats+")."});

  const r={
    id:id(),
    driverId:req.user.id,
    vehicleId:v.id,
    origin,
    destination,
    departureTime,
    availableSeats:n,
    status:"active"
  };
  db.routes.push(r);
  save(db);
  res.status(201).json(r);
});
app.get("/api/routes",(req,res)=>{
  const db=load();
  const out=db.routes.filter(r=>r.status==="active"&&r.availableSeats>0).map(r=>{
    const d=db.users.find(u=>u.id===r.driverId),v=db.vehicles.find(x=>x.id===r.vehicleId);
    return {...r,driverName:d?.name||"Desconocido",brand:v?.brand||"",model:v?.model||"",vehicleSeats:v?.seats||0};
  });
  res.json(out);
});
app.post("/api/routes/:id/pickup-points",auth,(req,res)=>{
  const db=load(),r=db.routes.find(x=>x.id===req.params.id&&x.driverId===req.user.id);
  if(!r)return res.status(404).json({error:"Ruta no encontrada"});
  if(!req.body.name)return res.status(400).json({error:"Falta el nombre del punto"});
  const p={id:id(),routeId:r.id,name:req.body.name,latitude:req.body.latitude??null,longitude:req.body.longitude??null,stopOrder:Number(req.body.stopOrder)||1};
  db.pickupPoints.push(p);save(db);res.status(201).json(p);
});
app.get("/api/routes/:id/pickup-points",(req,res)=>res.json(load().pickupPoints.filter(p=>p.routeId===req.params.id).sort((a,b)=>a.stopOrder-b.stopOrder)));
app.post("/api/bookings",auth,(req,res)=>{
  if(req.user.role!=="pasajero")return res.status(403).json({error:"Solo un pasajero puede reservar"});
  const db=load(),r=db.routes.find(x=>x.id===req.body.routeId&&x.status==="active");
  if(!r||r.availableSeats<1)return res.status(400).json({error:"No hay plazas disponibles"});
  const p=db.pickupPoints.find(x=>x.id===req.body.pickupPointId&&x.routeId===r.id);
  if(!p)return res.status(400).json({error:"Punto de recogida no válido"});
  const u=db.users.find(x=>x.id===req.user.id);
  if(u.tokens<1)return res.status(400).json({error:"No tienes tokens suficientes"});
  u.tokens--;r.availableSeats--;const b={id:id(),routeId:r.id,passengerId:u.id,pickupPointId:p.id,status:"pending",createdAt:new Date().toISOString()};
  db.bookings.push(b);db.tokenTransactions.push({id:id(),userId:u.id,amount:-1,reason:"Reserva de viaje",createdAt:new Date().toISOString()});save(db);res.status(201).json(b);
});


app.delete("/api/routes/:routeId/pickup-points/:pointId",auth,(req,res)=>{
  const db=load();
  const route=db.routes.find(r=>r.id===req.params.routeId && r.driverId===req.user.id);
  if(!route)return res.status(404).json({error:"Ruta no encontrada"});
  const index=db.pickupPoints.findIndex(p=>p.id===req.params.pointId && p.routeId===route.id);
  if(index===-1)return res.status(404).json({error:"Punto de recogida no encontrado"});
  db.pickupPoints.splice(index,1);
  db.pickupPoints.filter(p=>p.routeId===route.id).sort((a,b)=>a.stopOrder-b.stopOrder).forEach((p,i)=>p.stopOrder=i+1);
  save(db);
  res.json({ok:true});
});

app.get("/api/my-routes",auth,(req,res)=>{
  const db=load();
  const routes=db.routes.filter(r=>r.driverId===req.user.id).map(r=>{
    const v=db.vehicles.find(x=>x.id===r.vehicleId);
    const points=db.pickupPoints.filter(p=>p.routeId===r.id).sort((a,b)=>a.stopOrder-b.stopOrder);
    const bookings=db.bookings.filter(b=>b.routeId===r.id).map(b=>{
      const passenger=db.users.find(u=>u.id===b.passengerId);
      const point=points.find(p=>p.id===b.pickupPointId);
      return {id:b.id,status:b.status,passengerName:passenger?.name||"Usuario",passengerEmail:passenger?.email||"",pickupPoint:point?.name||"Punto",createdAt:b.createdAt};
    });
    return {...r,vehicle:v||null,pickupPoints:points,bookings};
  });
  res.json(routes);
});

app.get("/api/my-bookings",auth,(req,res)=>{
  const db=load();
  const bookings=db.bookings.filter(b=>b.passengerId===req.user.id).map(b=>{
    const r=db.routes.find(x=>x.id===b.routeId);
    const d=r ? db.users.find(u=>u.id===r.driverId) : null;
    const p=db.pickupPoints.find(x=>x.id===b.pickupPointId);
    return {...b,route:r||null,driverName:d?.name||"Desconocido",pickupPoint:p?.name||"Punto"};
  });
  res.json(bookings);
});

app.patch("/api/bookings/:id",auth,(req,res)=>{
  const db=load();
  const b=db.bookings.find(x=>x.id===req.params.id);
  if(!b)return res.status(404).json({error:"Reserva no encontrada"});
  const r=db.routes.find(x=>x.id===b.routeId);
  if(!r || r.driverId!==req.user.id)return res.status(403).json({error:"No tienes permiso"});
  if(!["accepted","rejected"].includes(req.body.status))return res.status(400).json({error:"Estado no válido"});
  if(b.status!=="pending")return res.status(400).json({error:"La reserva ya fue procesada"});
  if(req.body.status==="rejected"){
    const passenger=db.users.find(u=>u.id===b.passengerId);
    if(passenger){
      passenger.tokens+=1;
      db.tokenTransactions.push({id:id(),userId:passenger.id,amount:1,reason:"Devolución por reserva rechazada",createdAt:new Date().toISOString()});
      r.availableSeats+=1;
    }
  }
  b.status=req.body.status;
  save(db);
  res.json(b);
});

app.post("/api/tokens/reward",auth,(req,res)=>{
  const db=load(),u=db.users.find(x=>x.id===req.user.id);u.tokens+=5;
  db.tokenTransactions.push({id:id(),userId:u.id,amount:5,reason:"Recompensa de vídeo",createdAt:new Date().toISOString()});save(db);res.json({id:u.id,tokens:u.tokens});
});
app.get("/api/health",(req,res)=>res.json({ok:true,service:"RutaAero API",version:"0.2.1"}));
app.use((req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`RutaAero funcionando en http://localhost:${PORT}`));
