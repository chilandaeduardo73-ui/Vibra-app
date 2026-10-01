const vibraDB = require('./db');
import express from 'express';
import pg from 'pg';
const { Pool } = pg;
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import {fileURLToPath} from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const DB = path.join(__dirname, 'data.json');
const DATABASE_URL = process.env.DATABASE_URL || '';
const pool = DATABASE_URL ? new Pool({connectionString:DATABASE_URL, ssl: process.env.DATABASE_SSL === 'false' ? false : {rejectUnauthorized:false}}) : null;
let state = null;
let persistenceReady = false;
const sessions = new Map();
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const streams = new Map();
const rateBuckets = new Map();

// Baseline security headers. In production, keep HTTPS enabled and place a reverse proxy/WAF in front of the app.
app.disable('x-powered-by');
app.use((req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  if(req.secure || req.headers['x-forwarded-proto']==='https') res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains');
  next();
});

const seed = {eventReminders:[],eventSponsorships:[],users:[], posts:[], comments:[], likes:[], follows:[], messages:[], notifications:[], challenges:[], challengeResults:[], competitions:[], competitionEntries:[], liveEvents:[], eventParticipants:[], eventAnswers:[], businesses:[], campaigns:[], adEvents:[], topicFollows:[], communities:[], communityFollows:[], creators:[], creatorFollows:[], creatorOffers:[], creatorApplications:[], videoEvents:[], reports:[], blocks:[], privacySettings:[]};
function normalize(d){ for(const [k,v] of Object.entries(seed)) if(d[k]===undefined) d[k]=structuredClone(v); return d }
function read(){
  if(state) return state;
  try{state=normalize(JSON.parse(fs.readFileSync(DB,'utf8')))}catch{state=structuredClone(seed)}
  return state;
}
function write(d){
  state=d;
  const tmp=DB+'.tmp'; fs.writeFileSync(tmp,JSON.stringify(d,null,2)); fs.renameSync(tmp,DB);
  if(pool && persistenceReady){
    pool.query(`INSERT INTO app_state(id,data,updated_at) VALUES(1,$1::jsonb,NOW())
      ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data, updated_at=NOW()`,[JSON.stringify(d)]).catch(err=>console.error('DB persist failed:',err.message));
  }
}
async function initPersistence(){
  if(!pool){ persistenceReady=true; return; }
  await pool.query(`CREATE TABLE IF NOT EXISTS app_state (id INTEGER PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  const r=await pool.query('SELECT data FROM app_state WHERE id=1');
  if(r.rows[0]?.data){ state=normalize(r.rows[0].data); }
  else { state=read(); await pool.query(`INSERT INTO app_state(id,data) VALUES(1,$1::jsonb) ON CONFLICT(id) DO NOTHING`,[JSON.stringify(state)]); }
  persistenceReady=true;
} 
function id(){return crypto.randomUUID()}
function hash(password,salt=crypto.randomBytes(16).toString('hex')){return {salt,hash:crypto.scryptSync(password,salt,64).toString('hex')}}
function valid(password,salt,stored){try{return crypto.timingSafeEqual(Buffer.from(stored,'hex'),crypto.scryptSync(password,salt,64))}catch{return false}}
function safeUser(u){return u&&{id:u.id,username:u.username,name:u.name,bio:u.bio||'',avatar:u.avatar||'👤',createdAt:u.createdAt}}
function auth(req,res,next){const token=(req.headers.authorization||'').replace('Bearer ','');const session=sessions.get(token);if(!session)return res.status(401).json({error:'Não autenticado'});if(Date.now()-session.createdAt>SESSION_TTL_MS){sessions.delete(token);return res.status(401).json({error:'Sessão expirada. Entra novamente.'});}const uid=session.userId;const d=read();const u=d.users.find(x=>x.id===uid);if(!u)return res.status(401).json({error:'Sessão inválida'});req.user=u;req.token=token;next()}
function notify(d,userId,type,text,meta={}){if(!userId)return;const n={id:id(),userId,type,text,meta,read:false,createdAt:new Date().toISOString()};d.notifications.push(n);pushEvent(userId,'notification',n)}
function enrichPost(d,p,viewerId){const u=d.users.find(x=>x.id===p.userId);return {...p,user:safeUser(u),likes:d.likes.filter(l=>l.postId===p.id).length,liked:!!viewerId&&d.likes.some(l=>l.postId===p.id&&l.userId===viewerId),comments:d.comments.filter(c=>c.postId===p.id).length}}
app.use(express.json({limit:'25mb'}));
const MEDIA_DIR=path.join(__dirname,'uploads'); fs.mkdirSync(MEDIA_DIR,{recursive:true});
app.use('/media',express.static(MEDIA_DIR,{maxAge:'7d',immutable:true}));
app.post('/api/media',auth,(req,res)=>{
  const {dataUrl,kind='image'}=req.body||{};
  if(typeof dataUrl!=='string' || !dataUrl.startsWith('data:')) return res.status(400).json({error:'Ficheiro inválido.'});
  const m=dataUrl.match(/^data:(image\/(?:jpeg|png|webp|gif)|video\/(?:mp4|webm));base64,(.+)$/);
  if(!m) return res.status(400).json({error:'Formato não suportado. Usa JPG, PNG, WEBP, GIF, MP4 ou WEBM.'});
  const mime=m[1], raw=m[2];
  const buf=Buffer.from(raw,'base64');
  if(buf.length>20*1024*1024) return res.status(413).json({error:'O ficheiro excede 20 MB.'});
  const ext={
    'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif','video/mp4':'mp4','video/webm':'webm'
  }[mime];
  const filename=crypto.randomUUID()+'.'+ext;
  fs.writeFileSync(path.join(MEDIA_DIR,filename),buf);
  res.json({ok:true,url:'/media/'+filename,mime,size:buf.length,kind:String(kind).slice(0,20)});
});
app.use(express.static(path.join(__dirname,'public')));
app.get('/api/health',(req,res)=>res.json({ok:true,app:'VIBRA',version:'2.2.0',realtime:true,ads:true,creators:true,videoAnalytics:true,smartNotifications:true,eventCalendar:true,moderation:true,privacy:true}));
function rateLimit(key,limit=60,windowMs=60000){const now=Date.now();const b=rateBuckets.get(key);if(!b||now-b.start>windowMs){rateBuckets.set(key,{start:now,count:1});return true}b.count++;return b.count<=limit}
function guardRate(req,res,next){const key=(req.ip||'unknown')+'|'+req.path;if(!rateLimit(key,80,60000))return res.status(429).json({error:'Muitas solicitações. Tenta novamente daqui a pouco.'});next()}
app.use('/api/',guardRate);
function privacyFor(d,userId){let x=d.privacySettings.find(x=>x.userId===userId);if(!x){x={userId,profile:'public',messages:'everyone',createdAt:new Date().toISOString()};d.privacySettings.push(x)}return x}
function isBlocked(d,a,b){return d.blocks.some(x=>(x.blockerId===a&&x.blockedId===b)||(x.blockerId===b&&x.blockedId===a))}

function pushEvent(userId,event,data){const set=streams.get(userId);if(!set)return;const payload=`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;for(const res of set){try{res.write(payload)}catch{}}}
app.get('/api/events',(req,res)=>{const token=String(req.query.token||'');const session=sessions.get(token);if(!session || Date.now()-session.createdAt>SESSION_TTL_MS)return res.status(401).end();const uid=session.userId;res.setHeader('Content-Type','text/event-stream');res.setHeader('Cache-Control','no-cache');res.setHeader('Connection','keep-alive');res.flushHeaders?.();if(!streams.has(uid))streams.set(uid,new Set());streams.get(uid).add(res);res.write(`event: ready\ndata: ${JSON.stringify({ok:true})}\n\n`);const hb=setInterval(()=>{try{res.write(': ping\n\n')}catch{}},25000);req.on('close',()=>{clearInterval(hb);const set=streams.get(uid);set?.delete(res);if(set?.size===0)streams.delete(uid)})});

app.post('/api/register',(req,res)=>{const {username,name,password}=req.body||{};if(!username||!name||!password||password.length<6)return res.status(400).json({error:'Preenche nome, utilizador e palavra-passe com pelo menos 6 caracteres.'});const d=read();const clean=String(username).trim().replace(/[^a-zA-Z0-9_.-]/g,'').slice(0,30);if(!clean)return res.status(400).json({error:'Nome de utilizador inválido.'});if(d.users.some(u=>u.username.toLowerCase()===clean.toLowerCase()))return res.status(409).json({error:'Esse nome de utilizador já existe.'});const p=hash(password);const u={id:id(),username:clean,name:String(name).trim().slice(0,80),bio:'',avatar:'👤',salt:p.salt,passwordHash:p.hash,createdAt:new Date().toISOString()};d.users.push(u);write(d);const token=id();sessions.set(token,{userId:u.id,createdAt:Date.now()});res.json({token,user:safeUser(u)});});
app.post('/api/login',(req,res)=>{const ip=req.ip||'unknown';if(!rateLimit('login:'+ip,12,5*60*1000))return res.status(429).json({error:'Muitas tentativas de entrada. Tenta novamente mais tarde.'});const {username,password}=req.body||{};const d=read();const u=d.users.find(x=>x.username.toLowerCase()===String(username||'').trim().toLowerCase());if(!u||!valid(String(password||''),u.salt,u.passwordHash))return res.status(401).json({error:'Utilizador ou palavra-passe incorretos.'});const token=id();sessions.set(token,{userId:u.id,createdAt:Date.now()});res.json({token,user:safeUser(u)});});
app.post('/api/logout',auth,(req,res)=>{sessions.delete(req.token);res.json({ok:true})});
app.get('/api/me',auth,(req,res)=>res.json({user:safeUser(req.user)}));
app.patch('/api/me',auth,(req,res)=>{const d=read();const u=d.users.find(x=>x.id===req.user.id);if(req.body.name!==undefined)u.name=String(req.body.name).trim().slice(0,80);if(req.body.bio!==undefined)u.bio=String(req.body.bio).trim().slice(0,180);if(req.body.avatar!==undefined)u.avatar=String(req.body.avatar).slice(0,4);write(d);res.json({user:safeUser(u)})});
app.post('/api/me/password',auth,(req,res)=>{
  const {currentPassword,newPassword}=req.body||{};
  if(!currentPassword || !newPassword || String(newPassword).length<8)return res.status(400).json({error:'A nova palavra-passe deve ter pelo menos 8 caracteres.'});
  const d=read(); const u=d.users.find(x=>x.id===req.user.id);
  if(!u || !valid(String(currentPassword),u.salt,u.passwordHash))return res.status(401).json({error:'Palavra-passe atual incorreta.'});
  const p=hash(String(newPassword)); u.salt=p.salt; u.passwordHash=p.hash; write(d); res.json({ok:true});
});
app.delete('/api/me',auth,(req,res)=>{
  const d=read(); const uid=req.user.id;
  d.users=d.users.filter(x=>x.id!==uid); d.posts=d.posts.filter(x=>x.userId!==uid);
  d.comments=d.comments.filter(x=>x.userId!==uid); d.likes=d.likes.filter(x=>x.userId!==uid);
  d.follows=d.follows.filter(x=>x.followerId!==uid&&x.followingId!==uid);
  d.messages=d.messages.filter(x=>x.from!==uid&&x.to!==uid); d.notifications=d.notifications.filter(x=>x.userId!==uid);
  d.blocks=d.blocks.filter(x=>x.blockerId!==uid&&x.blockedId!==uid); d.privacySettings=d.privacySettings.filter(x=>x.userId!==uid);
  d.creators=d.creators.filter(x=>x.userId!==uid); d.creatorFollows=d.creatorFollows.filter(x=>x.userId!==uid);
  write(d); sessions.delete(req.token); res.json({ok:true});
});



// --- VIBRA Creators / Community v1.0 ---
function safeCreator(c,d){
 const u=d.users.find(x=>x.id===c.userId);
 const followers=d.creatorFollows.filter(x=>x.creatorId===c.id).length;
 const posts=d.posts.filter(x=>x.userId===c.userId).length;
 return {...c,user:safeUser(u),followers,posts};
}
app.get('/api/creators',auth,(req,res)=>{
 const d=read();
 const list=d.creators.map(c=>({...safeCreator(c,d),following:d.creatorFollows.some(x=>x.creatorId===c.id&&x.userId===req.user.id)})).sort((a,b)=>b.followers-a.followers);
 res.json({creators:list});
});
app.get('/api/creators/:id',auth,(req,res)=>{
 const d=read(); const c=d.creators.find(x=>x.id===req.params.id); if(!c)return res.status(404).json({error:'Criador não encontrado.'});
 const creator=safeCreator(c,d); creator.following=d.creatorFollows.some(x=>x.creatorId===c.id&&x.userId===req.user.id);
 creator.videos=d.posts.filter(x=>x.userId===c.userId&&x.videoUrl).slice(-12).reverse().map(p=>enrichPost(d,p,req.user.id));
 creator.postsList=d.posts.filter(x=>x.userId===c.userId).slice(-20).reverse().map(p=>enrichPost(d,p,req.user.id));
 res.json({creator});
});
app.post('/api/creators/apply',auth,(req,res)=>{
 const d=read(); let c=d.creators.find(x=>x.userId===req.user.id);
 if(c)return res.json({creator:safeCreator(c,d)});
 const cdata={id:id(),userId:req.user.id,stageName:String(req.body.stageName||req.user.name).trim().slice(0,100),category:String(req.body.category||'Criador').trim().slice(0,50),bio:String(req.body.bio||'').trim().slice(0,300),verified:false,createdAt:new Date().toISOString()};
 d.creators.push(cdata); write(d); res.status(201).json({creator:safeCreator(cdata,d)});
});
app.post('/api/creators/:id/follow',auth,(req,res)=>{
 const d=read(); const c=d.creators.find(x=>x.id===req.params.id); if(!c)return res.status(404).json({error:'Criador não encontrado.'});
 if(c.userId===req.user.id)return res.status(400).json({error:'Não podes seguir o teu próprio perfil de criador.'});
 const i=d.creatorFollows.findIndex(x=>x.creatorId===c.id&&x.userId===req.user.id);
 if(i>=0)d.creatorFollows.splice(i,1); else {d.creatorFollows.push({id:id(),creatorId:c.id,userId:req.user.id,createdAt:new Date().toISOString()}); notify(d,c.userId,'creator_follow',`${req.user.name} começou a seguir o teu perfil de criador.`,{creatorId:c.id});}
 write(d); res.json({following:i<0,followers:d.creatorFollows.filter(x=>x.creatorId===c.id).length});
});
app.patch('/api/creators/me',auth,(req,res)=>{
 const d=read(); const c=d.creators.find(x=>x.userId===req.user.id); if(!c)return res.status(404).json({error:'Ainda não tens perfil de criador.'});
 if(req.body.stageName!==undefined)c.stageName=String(req.body.stageName).trim().slice(0,100);
 if(req.body.category!==undefined)c.category=String(req.body.category).trim().slice(0,50);
 if(req.body.bio!==undefined)c.bio=String(req.body.bio).trim().slice(0,300);
 write(d); res.json({creator:safeCreator(c,d)});
});
app.get('/api/creators/me/stats',auth,(req,res)=>{
 const d=read(); const c=d.creators.find(x=>x.userId===req.user.id); if(!c)return res.status(404).json({error:'Ainda não tens perfil de criador.'});
 const posts=d.posts.filter(x=>x.userId===req.user.id); const ids=new Set(posts.map(x=>x.id)); const likes=d.likes.filter(x=>ids.has(x.postId)).length; const comments=d.comments.filter(x=>ids.has(x.postId)).length; const videos=posts.filter(x=>x.videoUrl).length;
 const ve=d.videoEvents.filter(e=>ids.has(e.postId));
 const views=new Set(ve.filter(e=>e.type==='view').map(e=>`${e.postId}:${e.userId}`)).size;
 const starts=ve.filter(e=>e.type==='start').length;
 const completes=ve.filter(e=>e.type==='complete').length;
 const watchSeconds=ve.filter(e=>e.type==='progress').reduce((n,e)=>n+Number(e.seconds||0),0);
 const completionRate=starts?Math.round(completes/starts*100):0;
 res.json({followers:d.creatorFollows.filter(x=>x.creatorId===c.id).length,posts:posts.length,videos,likes,comments,videoViews:views,videoStarts:starts,videoCompletes:completes,watchSeconds:Math.round(watchSeconds),completionRate});
});

app.post('/api/videos/:id/event',auth,(req,res)=>{
 const {type,seconds=0,position=0}=req.body||{};
 if(!['start','view','progress','complete'].includes(type))return res.status(400).json({error:'Evento de vídeo inválido.'});
 const d=read(); const p=d.posts.find(x=>x.id===req.params.id && x.videoUrl); if(!p)return res.status(404).json({error:'Vídeo não encontrado.'});
 if(type==='progress' && (!Number.isFinite(Number(seconds)) || Number(seconds)<0 || Number(seconds)>36000))return res.status(400).json({error:'Tempo inválido.'});
 d.videoEvents.push({id:id(),postId:p.id,userId:req.user.id,type,seconds:Number(seconds)||0,position:Number(position)||0,createdAt:new Date().toISOString()});
 write(d); res.json({ok:true});
});

app.get('/api/videos/:id/analytics',auth,(req,res)=>{
 const d=read(); const p=d.posts.find(x=>x.id===req.params.id && x.videoUrl); if(!p)return res.status(404).json({error:'Vídeo não encontrado.'});
 if(p.userId!==req.user.id)return res.status(403).json({error:'Apenas o criador pode ver estas métricas.'});
 const ev=d.videoEvents.filter(e=>e.postId===p.id);
 const views=new Set(ev.filter(e=>e.type==='view').map(e=>e.userId)).size;
 const starts=ev.filter(e=>e.type==='start').length; const completes=ev.filter(e=>e.type==='complete').length;
 const watchSeconds=Math.round(ev.filter(e=>e.type==='progress').reduce((n,e)=>n+Number(e.seconds||0),0));
 res.json({videoId:p.id,views,starts,completes,watchSeconds,completionRate:starts?Math.round(completes/starts*100):0,likes:d.likes.filter(x=>x.postId===p.id).length,comments:d.comments.filter(x=>x.postId===p.id).length});
});

// --- VIBRA Creator Marketplace v1.1 ---
function safeOffer(o,d){const b=d.businesses.find(x=>x.id===o.businessId);const c=d.creators.find(x=>x.id===o.creatorId);return {...o,business:b?safeBusiness(b):null,creator:c?safeCreator(c,d):null};}
app.get('/api/creator-marketplace/creators',auth,(req,res)=>{const d=read();const q=String(req.query.q||'').toLowerCase().trim();let list=d.creators.map(c=>safeCreator(c,d));if(q)list=list.filter(c=>`${c.stageName} ${c.category} ${c.user?.name||''}`.toLowerCase().includes(q));res.json({creators:list.sort((a,b)=>b.followers-a.followers).slice(0,50)});});
app.post('/api/creator-marketplace/offers',auth,(req,res)=>{const {businessId,creatorId,title,description,budget=0,deliverables=''}=req.body||{};const d=read();const b=d.businesses.find(x=>x.id===businessId&&x.ownerId===req.user.id);const c=d.creators.find(x=>x.id===creatorId);if(!b||!c)return res.status(404).json({error:'Empresa ou criador não encontrado.'});if(c.userId===req.user.id)return res.status(400).json({error:'Não podes enviar uma proposta para ti próprio.'});if(!String(title||'').trim()||!String(description||'').trim())return res.status(400).json({error:'Título e descrição são obrigatórios.'});const offer={id:id(),businessId,creatorId,title:String(title).trim().slice(0,120),description:String(description).trim().slice(0,1000),budget:Number(budget)||0,deliverables:String(deliverables||'').trim().slice(0,500),status:'pending',createdAt:new Date().toISOString()};d.creatorOffers.push(offer);notify(d,c.userId,'creator_offer',`${b.name} enviou uma proposta de parceria: ${offer.title}.`,{offerId:offer.id});write(d);res.status(201).json({offer:safeOffer(offer,d)});});
app.get('/api/creator-marketplace/offers',auth,(req,res)=>{const d=read();const mineCreator=d.creators.find(c=>c.userId===req.user.id);const mineBusinesses=new Set(d.businesses.filter(b=>b.ownerId===req.user.id).map(b=>b.id));let offers=d.creatorOffers.filter(o=>mineBusinesses.has(o.businessId)||(mineCreator&&o.creatorId===mineCreator.id)).map(o=>safeOffer(o,d)).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));res.json({offers});});
app.patch('/api/creator-marketplace/offers/:id',auth,(req,res)=>{const d=read();const o=d.creatorOffers.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:'Proposta não encontrada.'});const c=d.creators.find(x=>x.id===o.creatorId);const b=d.businesses.find(x=>x.id===o.businessId);const allowed=c?.userId===req.user.id||b?.ownerId===req.user.id;if(!allowed)return res.status(403).json({error:'Sem permissão.'});const status=String(req.body.status||'').toLowerCase();if(!['accepted','declined','cancelled'].includes(status))return res.status(400).json({error:'Estado inválido.'});o.status=status;o.updatedAt=new Date().toISOString();if(c?.userId===req.user.id&&b)notify(d,b.ownerId,'creator_offer_update',`${c.stageName} ${status==='accepted'?'aceitou':'recusou'} a proposta “${o.title}”.`,{offerId:o.id,status});write(d);res.json({offer:safeOffer(o,d)});});
// --- VIBRA Ads / Business ---
function safeBusiness(b){return b&&{id:b.id,name:b.name,description:b.description||'',logo:b.logo||'🏢',ownerId:b.ownerId,createdAt:b.createdAt}}
function safeCampaign(c,b){return {...c,business:b?safeBusiness(b):null}}
app.post('/api/businesses',auth,(req,res)=>{const {name,description='',logo='🏢'}=req.body||{};if(!String(name||'').trim())return res.status(400).json({error:'Nome da empresa é obrigatório.'});const d=read();const b={id:id(),ownerId:req.user.id,name:String(name).trim().slice(0,100),description:String(description||'').trim().slice(0,300),logo:String(logo||'🏢').slice(0,4),createdAt:new Date().toISOString()};d.businesses.push(b);write(d);res.status(201).json({business:safeBusiness(b)})});
app.get('/api/businesses/mine',auth,(req,res)=>{const d=read();res.json({businesses:d.businesses.filter(b=>b.ownerId===req.user.id).map(safeBusiness)})});
app.post('/api/campaigns',auth,(req,res)=>{const {businessId,title,text,image='',link='',category='Geral',budget=0}=req.body||{};const d=read();const b=d.businesses.find(x=>x.id===businessId&&x.ownerId===req.user.id);if(!b)return res.status(403).json({error:'Empresa não encontrada.'});if(!String(title||'').trim()||!String(text||'').trim())return res.status(400).json({error:'Título e texto são obrigatórios.'});const c={id:id(),businessId,title:String(title).trim().slice(0,100),text:String(text).trim().slice(0,500),image:String(image||'').slice(0,1500000),link:String(link||'').trim().slice(0,500),category:String(category||'Geral').slice(0,40),budget:Math.max(0,Number(budget)||0),status:'active',createdAt:new Date().toISOString()};d.campaigns.push(c);write(d);res.status(201).json({campaign:safeCampaign(c,b)})});
app.get('/api/campaigns/mine',auth,(req,res)=>{const d=read();const mine=d.businesses.filter(b=>b.ownerId===req.user.id).map(b=>b.id);const campaigns=d.campaigns.filter(c=>mine.includes(c.businessId)).map(c=>safeCampaign(c,d.businesses.find(b=>b.id===c.businessId)));res.json({campaigns})});
app.get('/api/ads',auth,(req,res)=>{const d=read();const active=d.campaigns.filter(c=>c.status==='active');const chosen=active.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,5).map(c=>safeCampaign(c,d.businesses.find(b=>b.id===c.businessId)));res.json({ads:chosen})});
app.post('/api/ads/:id/event',auth,(req,res)=>{const {type}=req.body||{};if(!['impression','click'].includes(type))return res.status(400).json({error:'Evento inválido.'});const d=read();const c=d.campaigns.find(x=>x.id===req.params.id);if(!c)return res.status(404).json({error:'Campanha não encontrada.'});d.adEvents.push({id:id(),campaignId:c.id,userId:req.user.id,type,createdAt:new Date().toISOString()});write(d);res.json({ok:true})});

// --- VIBRA Event Sponsorships v1.8 ---
function ensureEventSponsorships(d){ d.eventSponsorships ||= []; }
function sponsorshipView(d,s){ const e=d.liveEvents.find(x=>x.id===s.eventId); const b=d.businesses.find(x=>x.id===s.businessId); const ev=d.adEvents.filter(x=>x.sponsorshipId===s.id); return {...s,event:e?{id:e.id,title:e.title,startsAt:e.startsAt,endsAt:e.endsAt,communityId:e.communityId,status:liveStatus(e)}:null,business:b?safeBusiness(b):null,metrics:{impressions:ev.filter(x=>x.type==='impression').length,clicks:ev.filter(x=>x.type==='click').length,participants:e?d.eventParticipants.filter(x=>x.eventId===e.id).length:0}}; }
app.get('/api/event-sponsorships',auth,(req,res)=>{ const d=read(); ensureEventSponsorships(d); const mine=d.businesses.filter(b=>b.ownerId===req.user.id).map(b=>b.id); res.json({sponsorships:d.eventSponsorships.filter(s=>mine.includes(s.businessId)).map(s=>sponsorshipView(d,s))}); });
app.get('/api/event-sponsorships/opportunities',auth,(req,res)=>{ const d=read(); ensureLiveEvents(d); const events=d.liveEvents.filter(e=>Date.parse(e.endsAt)>=Date.now()).sort((a,b)=>Date.parse(a.startsAt)-Date.parse(b.startsAt)).map(e=>({...eventView(d,e,req.user.id),sponsorshipOpen:true})); res.json({events}); });
app.post('/api/event-sponsorships',auth,(req,res)=>{ const {businessId,eventId,title,amount=0,description='',creativeUrl=''}=req.body||{}; const d=read(); ensureEventSponsorships(d); const b=d.businesses.find(x=>x.id===businessId&&x.ownerId===req.user.id); const e=d.liveEvents.find(x=>x.id===eventId); if(!b)return res.status(403).json({error:'Empresa não encontrada.'}); if(!e)return res.status(404).json({error:'Evento não encontrado.'}); if(!String(title||'').trim())return res.status(400).json({error:'Título da campanha é obrigatório.'}); const s={id:id(),businessId,eventId,title:String(title).trim().slice(0,120),amount:Math.max(0,Number(amount)||0),description:String(description||'').trim().slice(0,500),creativeUrl:String(creativeUrl||'').trim().slice(0,1000),status:'pending',createdAt:new Date().toISOString()}; d.eventSponsorships.push(s); e.sponsor=b.name; notify(d,e.createdBy||'', 'event_sponsorship', `📢 Nova proposta de patrocínio para ${e.title}.`,{sponsorshipId:s.id,eventId:e.id}); write(d); res.status(201).json({sponsorship:sponsorshipView(d,s)}); });
app.post('/api/event-sponsorships/:id/status',auth,(req,res)=>{ const d=read(); ensureEventSponsorships(d); const s=d.eventSponsorships.find(x=>x.id===req.params.id); if(!s)return res.status(404).json({error:'Patrocínio não encontrado.'}); const b=d.businesses.find(x=>x.id===s.businessId); if(!b||b.ownerId!==req.user.id)return res.status(403).json({error:'Sem permissão.'}); const status=String(req.body?.status||''); if(!['pending','active','paused','ended'].includes(status))return res.status(400).json({error:'Estado inválido.'}); s.status=status; if(status==='active'){const e=d.liveEvents.find(x=>x.id===s.eventId);if(e)e.sponsor=b.name;} write(d); res.json({sponsorship:sponsorshipView(d,s)}); });
app.get('/api/ads/dashboard',auth,(req,res)=>{const d=read();const mine=d.businesses.filter(b=>b.ownerId===req.user.id).map(b=>b.id);const campaigns=d.campaigns.filter(c=>mine.includes(c.businessId));const ids=new Set(campaigns.map(c=>c.id));const events=d.adEvents.filter(e=>ids.has(e.campaignId));res.json({campaigns:campaigns.map(c=>{const ev=events.filter(e=>e.campaignId===c.id);return {...safeCampaign(c,d.businesses.find(b=>b.id===c.businessId)),impressions:ev.filter(e=>e.type==='impression').length,clicks:ev.filter(e=>e.type==='click').length}}),totals:{impressions:events.filter(e=>e.type==='impression').length,clicks:events.filter(e=>e.type==='click').length}})});


// --- VIBRA Discovery / Entertainment ---
const discoverySeed={
 topics:[
  {id:'famosos',title:'Famosos',icon:'⭐',description:'Artistas, criadores e personalidades em destaque.',kind:'entertainment'},
  {id:'novelas',title:'Novelas & Séries',icon:'🎬',description:'Sugestões, elenco e conversas sobre televisão.',kind:'entertainment'},
  {id:'musica',title:'Música',icon:'🎵',description:'Cantores, lançamentos e tendências.',kind:'entertainment'},
  {id:'futebol',title:'Futebol',icon:'⚽',description:'Notícias, debates e desafios.',kind:'sports'},
  {id:'angola',title:'Angola',icon:'🇦🇴',description:'Assuntos e tendências da comunidade.',kind:'local'},
  {id:'cinema',title:'Cinema',icon:'🍿',description:'Filmes, atores e recomendações.',kind:'entertainment'}
 ],
 stories:[
  {id:'s1',title:'Em alta no VIBRA',summary:'Descobre os assuntos que estão a gerar mais conversa hoje.',category:'Tendências',icon:'🔥'},
  {id:'s2',title:'Novela para descobrir',summary:'Uma seleção de novelas e séries para acompanhar e comentar.',category:'Novelas',icon:'🎬'},
  {id:'s3',title:'Som do momento',summary:'Descobre artistas e músicas que estão a movimentar a comunidade.',category:'Música',icon:'🎵'},
  {id:'s4',title:'Debate de futebol',summary:'Entra na conversa e desafia os teus amigos.',category:'Futebol',icon:'⚽'}
 ]
};
app.get('/api/discovery',(req,res)=>res.json(discoverySeed));
app.get('/api/discovery/search',auth,(req,res)=>{const q=String(req.query.q||'').trim().toLowerCase();if(!q)return res.json({topics:discoverySeed.topics,stories:discoverySeed.stories,users:[]});const d=read();const users=d.users.filter(u=>(u.name+' '+u.username).toLowerCase().includes(q)).slice(0,12).map(safeUser);const topics=discoverySeed.topics.filter(t=>(t.title+' '+t.description).toLowerCase().includes(q));const stories=discoverySeed.stories.filter(x=>(x.title+' '+x.summary+' '+x.category).toLowerCase().includes(q));res.json({users,topics,stories});});
app.get('/api/trending',auth,(req,res)=>{const d=read();const counts={};for(const p of d.posts){const k=p.category||'Geral';counts[k]=(counts[k]||0)+1}const topicCounts=discoverySeed.topics.map(t=>({...t,count:counts[t.title]||counts[t.id]||0})).sort((a,b)=>b.count-a.count);res.json({topics:topicCounts,stories:discoverySeed.stories});});


// --- VIBRA v0.8 Content & Personalization ---
const editorialSeed = [
 {id:'c1',type:'news',topic:'angola',title:'VIBRA Agora: espaço para assuntos que movimentam Angola',summary:'Conteúdo editorial de demonstração. Na produção, cada notícia será ligada à sua fonte e data de publicação.',sourceName:'VIBRA Editorial',sourceUrl:'',publishedAt:new Date().toISOString()},
 {id:'c2',type:'entertainment',topic:'famosos',title:'Famosos: acompanhe novidades e conversas da comunidade',summary:'Área dedicada a artistas, atores, criadores e personalidades públicas, com informação atribuída a fontes.',sourceName:'VIBRA Editorial',sourceUrl:'',publishedAt:new Date().toISOString()},
 {id:'c3',type:'series',topic:'novelas',title:'Novelas & Séries: descubra o que assistir',summary:'Recomendações e discussões sobre novelas e séries. O VIBRA poderá indicar onde o conteúdo está disponível.',sourceName:'VIBRA Editorial',sourceUrl:'',publishedAt:new Date().toISOString()},
 {id:'c4',type:'music',topic:'musica',title:'Música: artistas, lançamentos e tendências',summary:'Uma área para descobrir músicas e conversar sobre novos lançamentos.',sourceName:'VIBRA Editorial',sourceUrl:'',publishedAt:new Date().toISOString()},
 {id:'c5',type:'sports',topic:'futebol',title:'Futebol: notícias, debates e desafios',summary:'Conteúdo esportivo e desafios da comunidade.',sourceName:'VIBRA Editorial',sourceUrl:'',publishedAt:new Date().toISOString()}
];
if(!seed.topicFollows) seed.topicFollows=[];
function contentForUser(d,uid){const followed=new Set(d.topicFollows.filter(x=>x.userId===uid).map(x=>x.topic));return editorialSeed.map(x=>({...x,personal:followed.has(x.topic)})).sort((a,b)=>Number(b.personal)-Number(a.personal));}
app.get('/api/content',auth,(req,res)=>{const d=read();let items=contentForUser(d,req.user.id);const topic=String(req.query.topic||'').trim();if(topic)items=items.filter(x=>x.topic===topic);res.json({items,followed:[...new Set(d.topicFollows.filter(x=>x.userId===req.user.id).map(x=>x.topic))]});});
app.get('/api/content/:id',auth,(req,res)=>{const item=editorialSeed.find(x=>x.id===req.params.id);if(!item)return res.status(404).json({error:'Conteúdo não encontrado'});res.json({item});});
app.post('/api/topics/:topic/follow',auth,(req,res)=>{const topic=String(req.params.topic).trim().toLowerCase();if(!discoverySeed.topics.some(x=>x.id===topic))return res.status(404).json({error:'Assunto não encontrado'});const d=read();const i=d.topicFollows.findIndex(x=>x.userId===req.user.id&&x.topic===topic);if(i>=0)d.topicFollows.splice(i,1);else d.topicFollows.push({id:id(),userId:req.user.id,topic,createdAt:new Date().toISOString()});write(d);res.json({following:i<0,topic});});
app.get('/api/topics/following',auth,(req,res)=>{const d=read();res.json({topics:[...new Set(d.topicFollows.filter(x=>x.userId===req.user.id).map(x=>x.topic))]});});


// --- VIBRA Communities v1.4 ---
const communitySeed=[
 {id:'futebol',name:'Futebol',emoji:'⚽',description:'Jogos, opiniões, desafios, notícias e conversa entre fãs.',color:'violet'},
 {id:'musica',name:'Música',emoji:'🎵',description:'Cantores, lançamentos, clipes, descobertas e debates musicais.',color:'pink'},
 {id:'novelas',name:'Novelas & Séries',emoji:'🎬',description:'Novelas, séries, personagens, teorias e recomendações.',color:'cyan'},
 {id:'angola',name:'Angola',emoji:'🇦🇴',description:'Assuntos, cultura, entretenimento e acontecimentos de Angola.',color:'green'},
 {id:'humor',name:'Humor',emoji:'😂',description:'Memes, situações, histórias e desafios para rir.',color:'gold'},
 {id:'gaming',name:'Gaming',emoji:'🎮',description:'Jogos, jogadores, novidades, competições e comunidade gamer.',color:'violet'}
];
function ensureCommunities(d){if(!d.communities.length){d.communities=communitySeed.map(x=>({...x,createdAt:new Date().toISOString()}));write(d)}}
function communityScore(d,cid){const posts=d.posts.filter(p=>String(p.category||'').toLowerCase()===cid||String(p.category||'').toLowerCase()===communitySeed.find(x=>x.id===cid)?.name.toLowerCase());const ids=new Set(posts.map(p=>p.id));const likes=d.likes.filter(x=>ids.has(x.postId)).length;const comments=d.comments.filter(x=>ids.has(x.postId)).length;return posts.length*3+likes*2+comments*3}
app.get('/api/communities',auth,(req,res)=>{const d=read();ensureCommunities(d);const list=d.communities.map(c=>({c,...c,followers:d.communityFollows.filter(x=>x.communityId===c.id).length,posts:d.posts.filter(p=>String(p.category||'').toLowerCase()===c.id||String(p.category||'').toLowerCase()===c.name.toLowerCase()).length,following:d.communityFollows.some(x=>x.communityId===c.id&&x.userId===req.user.id),score:communityScore(d,c.id)})).sort((a,b)=>b.score-a.score);res.json({communities:list})});
app.get('/api/communities/:id',auth,(req,res)=>{const d=read();ensureCommunities(d);const c=d.communities.find(x=>x.id===req.params.id);if(!c)return res.status(404).json({error:'Comunidade não encontrada.'});const posts=d.posts.filter(p=>String(p.category||'').toLowerCase()===c.id||String(p.category||'').toLowerCase()===c.name.toLowerCase()).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,50).map(p=>enrichPost(d,p,req.user.id));const followers=d.communityFollows.filter(x=>x.communityId===c.id).length;const following=d.communityFollows.some(x=>x.communityId===c.id&&x.userId===req.user.id);const ranking=[...new Set(posts.map(p=>p.userId))].map(uid=>{const u=d.users.find(x=>x.id===uid);const own=posts.filter(p=>p.userId===uid);const pts=own.reduce((n,p)=>n+p.likes*2+p.comments*3+5,0);return {user:safeUser(u),points:pts,posts:own.length}}).sort((a,b)=>b.points-a.points).slice(0,10);res.json({community:{...c,followers,following,posts:posts.length},posts,ranking,trending:posts.slice(0,5).map(p=>({id:p.id,user:p.user,text:p.text,likes:p.likes,comments:p.comments}))})});
app.post('/api/communities/:id/follow',auth,(req,res)=>{const d=read();ensureCommunities(d);const c=d.communities.find(x=>x.id===req.params.id);if(!c)return res.status(404).json({error:'Comunidade não encontrada.'});const i=d.communityFollows.findIndex(x=>x.communityId===c.id&&x.userId===req.user.id);if(i>=0)d.communityFollows.splice(i,1);else d.communityFollows.push({id:id(),communityId:c.id,userId:req.user.id,createdAt:new Date().toISOString()});write(d);res.json({following:i<0,followers:d.communityFollows.filter(x=>x.communityId===c.id).length})});
app.get('/api/communities/:id/feed',auth,(req,res)=>{const d=read();ensureCommunities(d);const c=d.communities.find(x=>x.id===req.params.id);if(!c)return res.status(404).json({error:'Comunidade não encontrada.'});const posts=d.posts.filter(p=>String(p.category||'').toLowerCase()===c.id||String(p.category||'').toLowerCase()===c.name.toLowerCase()).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).map(p=>enrichPost(d,p,req.user.id));res.json({posts})});

app.get('/api/videos',auth,(req,res)=>{const d=read();const posts=[...d.posts].filter(p=>p.videoUrl).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).map(p=>enrichPost(d,p,req.user.id));res.json({videos:posts});});

function personalizedFeed(d,uid){
 const following=new Set(d.follows.filter(f=>f.followerId===uid).map(f=>f.followingId));
 const followedTopics=new Set((d.topicFollows||[]).filter(x=>x.userId===uid).map(x=>x.topic));
 const likedPostIds=new Set(d.likes.filter(x=>x.userId===uid).map(x=>x.postId));
 const commentedPostIds=new Set(d.comments.filter(x=>x.userId===uid).map(x=>x.postId));
 const scores={};
 const categoryInterest={};
 for(const p of d.posts){
   if(likedPostIds.has(p.id)||commentedPostIds.has(p.id)||following.has(p.userId)) categoryInterest[p.category]=(categoryInterest[p.category]||0)+(likedPostIds.has(p.id)?2:0)+(commentedPostIds.has(p.id)?3:0)+(following.has(p.userId)?2:0);
 }
 const now=Date.now();
 return [...d.posts].filter(p=>!isBlocked(d,uid,p.userId)).map(p=>{
   const age=Math.max(0,(now-new Date(p.createdAt).getTime())/3600000);
   const recency=Math.max(0,36-age)/6;
   let score=recency;
   if(following.has(p.userId)) score+=8;
   if(followedTopics.has(String(p.category||'').toLowerCase())) score+=7;
   score+=Math.min(8,categoryInterest[p.category]||0);
   if(likedPostIds.has(p.id)) score+=2;
   if(commentedPostIds.has(p.id)) score+=3;
   score+=Math.min(5,(d.likes.filter(x=>x.postId===p.id).length*0.15));
   score+=Math.min(4,(d.comments.filter(x=>x.postId===p.id).length*0.2));
   return {...enrichPost(d,p,uid),followingAuthor:following.has(p.userId),personalScore:Math.round(score*100)/100};
 }).sort((a,b)=>b.personalScore-a.personalScore);
}
app.get('/api/feed',auth,(req,res)=>{const d=read();const posts=personalizedFeed(d,req.user.id);res.json({posts,algorithm:{version:'v1',signals:['recência','pessoas seguidas','assuntos seguidos','interações anteriores','atividade da comunidade']}});});
app.post('/api/posts',auth,(req,res)=>{const {text,category='Geral',image='',videoUrl=''}=req.body||{};if(!text?.trim()&&!image)return res.status(400).json({error:'Adiciona texto ou imagem.'});const d=read();const p={id:id(),userId:req.user.id,text:String(text||'').trim().slice(0,1500),category:String(category||'Geral').slice(0,40),image:String(image||'').slice(0,1500000),videoUrl:String(videoUrl||'').trim().slice(0,2000),createdAt:new Date().toISOString()};d.posts.push(p);write(d);res.status(201).json({post:enrichPost(d,p,req.user.id)});});
app.delete('/api/posts/:id',auth,(req,res)=>{const d=read();const p=d.posts.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:'Publicação não encontrada'});if(p.userId!==req.user.id)return res.status(403).json({error:'Sem permissão'});d.posts=d.posts.filter(x=>x.id!==p.id);d.likes=d.likes.filter(x=>x.postId!==p.id);d.comments=d.comments.filter(x=>x.postId!==p.id);write(d);res.json({ok:true})});
app.post('/api/posts/:id/like',auth,(req,res)=>{const d=read();const p=d.posts.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:'Publicação não encontrada'});const i=d.likes.findIndex(l=>l.postId===p.id&&l.userId===req.user.id);if(i>=0)d.likes.splice(i,1);else{d.likes.push({id:id(),postId:p.id,userId:req.user.id});if(p.userId!==req.user.id)notify(d,p.userId,'like',`${req.user.name} gostou da tua publicação.`,{postId:p.id})}write(d);res.json({liked:i<0,likes:d.likes.filter(l=>l.postId===p.id).length});});
app.get('/api/posts/:id/comments',(req,res)=>{const d=read();const comments=d.comments.filter(c=>c.postId===req.params.id).sort((a,b)=>new Date(a.createdAt)-new Date(b.createdAt)).map(c=>({...c,user:safeUser(d.users.find(u=>u.id===c.userId))}));res.json({comments});});
app.post('/api/posts/:id/comments',auth,(req,res)=>{const {text}=req.body||{};if(!text?.trim())return res.status(400).json({error:'Comentário vazio.'});const d=read();const p=d.posts.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:'Publicação não encontrada'});const c={id:id(),postId:req.params.id,userId:req.user.id,text:String(text).trim().slice(0,500),createdAt:new Date().toISOString()};d.comments.push(c);if(p.userId!==req.user.id)notify(d,p.userId,'comment',`${req.user.name} comentou na tua publicação.`,{postId:p.id});write(d);res.status(201).json({comment:{...c,user:safeUser(req.user)}});});

app.get('/api/users/search',(req,res)=>{const q=String(req.query.q||'').toLowerCase().trim();const d=read();const users=d.users.filter(u=>!q||u.name.toLowerCase().includes(q)||u.username.toLowerCase().includes(q)).slice(0,30).map(u=>safeUser(u));res.json({users});});
app.get('/api/users/:id',(req,res)=>{const d=read();const u=d.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'Não encontrado'});const followers=d.follows.filter(f=>f.followingId===u.id).length;const following=d.follows.filter(f=>f.followerId===u.id).length;const isFollowing=!!req.headers.authorization&&(()=>{const t=(req.headers.authorization||'').replace('Bearer ','');const session=sessions.get(t);const uid=session?.userId;return !!uid&&d.follows.some(f=>f.followerId===uid&&f.followingId===u.id)})();res.json({user:safeUser(u),followers,following,posts:d.posts.filter(p=>p.userId===u.id).length,isFollowing});});
app.post('/api/users/:id/follow',auth,(req,res)=>{if(req.params.id===req.user.id)return res.status(400).json({error:'Não podes seguir a ti próprio.'});const d=read();const target=d.users.find(u=>u.id===req.params.id);if(!target)return res.status(404).json({error:'Utilizador não encontrado'});const i=d.follows.findIndex(f=>f.followerId===req.user.id&&f.followingId===target.id);if(i>=0)d.follows.splice(i,1);else{d.follows.push({id:id(),followerId:req.user.id,followingId:target.id});notify(d,target.id,'follow',`${req.user.name} começou a seguir-te.`)}write(d);res.json({following:i<0});});

app.get('/api/messages',auth,(req,res)=>{const d=read();const peer=req.query.with;let rows=d.messages.filter(m=>m.from===req.user.id||m.to===req.user.id);if(peer)rows=rows.filter(m=>(m.from===req.user.id&&m.to===peer)||(m.to===req.user.id&&m.from===peer));rows.sort((a,b)=>new Date(a.createdAt)-new Date(b.createdAt));res.json({messages:rows.map(m=>({...m,fromUser:safeUser(d.users.find(u=>u.id===m.from)),toUser:safeUser(d.users.find(u=>u.id===m.to))}))});});
app.post('/api/messages',auth,(req,res)=>{const {to,text}=req.body||{};const d=read();const target=d.users.find(u=>u.id===to);if(!target)return res.status(404).json({error:'Utilizador não encontrado'});if(isBlocked(d,req.user.id,to))return res.status(403).json({error:'Não é possível enviar mensagens entre estas contas.'});const privacy=privacyFor(d,to);const follows=d.follows.some(x=>x.followerId===to&&x.followingId===req.user.id);if(privacy.messages==='nobody'||(privacy.messages==='followers'&&!follows))return res.status(403).json({error:'Este utilizador não aceita mensagens desta conta.'});if(!text?.trim())return res.status(400).json({error:'Mensagem vazia.'});const m={id:id(),from:req.user.id,to,text:String(text).trim().slice(0,1500),createdAt:new Date().toISOString()};d.messages.push(m);notify(d,to,'message',`${req.user.name} enviou-te uma mensagem.`,{from:req.user.id});pushEvent(to,'message',m);pushEvent(req.user.id,'message',m);write(d);res.status(201).json({message:m});});

app.get('/api/notifications',auth,(req,res)=>{const d=read();const list=d.notifications.filter(n=>n.userId===req.user.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,50);res.json({notifications:list,unread:list.filter(n=>!n.read).length});});
app.post('/api/notifications/read',auth,(req,res)=>{const d=read();d.notifications.filter(n=>n.userId===req.user.id).forEach(n=>n.read=true);write(d);res.json({ok:true})});

const questions=[
 {q:'Qual é o maior planeta do Sistema Solar?',a:['Terra','Júpiter','Marte','Vénus'],c:1},
 {q:'Qual país é conhecido como país do sol nascente?',a:['Japão','Egito','México','Canadá'],c:0},
 {q:'Qual instrumento tem teclas, pedais e cordas?',a:['Violino','Piano','Flauta','Tambor'],c:1},
 {q:'Qual é a capital de Angola?',a:['Benguela','Huambo','Luanda','Lubango'],c:2},
 {q:'Quantos lados tem um hexágono?',a:['5','6','7','8'],c:1},
 {q:'Qual destes é um mamífero?',a:['Tubarão','Golfinho','Crocodilo','Tartaruga'],c:1},
 {q:'Qual continente é Angola?',a:['África','Europa','Ásia','Oceania'],c:0},
 {q:'Qual é a língua oficial de Angola?',a:['Francês','Português','Inglês','Espanhol'],c:1},
 {q:'Qual cor resulta de azul + amarelo?',a:['Roxo','Laranja','Verde','Rosa'],c:2},
 {q:'Quantos minutos tem uma hora?',a:['30','45','60','90'],c:2}
];

// --- VIBRA Community Competitions v1.5 ---
const competitionSeed={
  futebol:[['Quem venceu o Mundial de 2022?',['Argentina','França','Brasil','Croácia'],0],['Quantos jogadores começa uma equipa em campo?',['9','10','11','12'],2],['Qual cartão significa expulsão?',['Amarelo','Azul','Vermelho','Verde'],2]],
  musica:[['Qual instrumento tem teclas e cordas?',['Piano','Tambor','Flauta','Violino'],0],['Qual destes é um género musical?',['Kizomba','Satélite','Cometa','Atlântico'],0],['Uma canção normalmente tem…',['Verso e refrão','Planta e raiz','Motor e roda','Mapa e bússola'],0]],
  novelas:[['O que é um episódio?',['Parte de uma série','Tipo de instrumento','Competição','Jogo de futebol'],0],['Quem interpreta personagens numa novela?',['Atores','Árbitros','Pilotos','Narradores'],0],['O que normalmente continua de um episódio para outro?',['A história','O estádio','A temperatura','O calendário'],0]],
  angola:[['Qual é a capital de Angola?',['Luanda','Benguela','Huambo','Lubango'],0],['Qual é a moeda de Angola?',['Kwanza','Euro','Dólar','Metical'],0],['Qual destes é um rio de Angola?',['Kwanza','Nilo','Amazonas','Danúbio'],0]],
  humor:[['O que costuma provocar uma gargalhada?',['Uma piada','Um contrato','Uma fatura','Um mapa'],0],['O humor pode ser usado para…',['Entreter','Calcular impostos','Medir distância','Cozinhar'],0],['Uma comédia é geralmente associada a…',['Humor','Suspense policial','Documentação técnica','Meteorologia'],0]],
  gaming:[['O que significa “NPC” em muitos jogos?',['Personagem não jogável','Novo pacote de código','Nível por campeonato','Nome de jogador campeão'],0],['O que é um “checkpoint”?',['Ponto de progresso','Tipo de arma real','Canal de televisão','Conta bancária'],0],['O que normalmente representa XP?',['Experiência','Preço','Velocidade','Energia elétrica'],0]]
};
function ensureCompetitions(d){
  if(d.competitions.length)return;
  const now=new Date(); const end=new Date(now.getTime()+7*24*3600000);
  d.competitions=[];
  for(const [cid,qs] of Object.entries(competitionSeed)){
    d.competitions.push({id:id(),communityId:cid,title:'Batalha da Comunidade',subtitle:'3 perguntas · ranking ao vivo',status:'open',startsAt:now.toISOString(),endsAt:end.toISOString(),createdAt:now.toISOString(),questions:qs.map((q,i)=>({id:`${cid}-${i}`,q:q[0],a:q[1],c:q[2]}))});
  }
  write(d);
}

// --- VIBRA Live Events v1.6 ---
function ensureLiveEvents(d){
  d.liveEvents ||= []; d.eventParticipants ||= []; d.eventAnswers ||= [];
  if(d.liveEvents.length) return;
  ensureCompetitions(d);
  const now=Date.now();
  d.liveEvents=d.competitions.map((c,i)=>({
    id:id(), communityId:c.communityId, competitionId:c.id,
    title:`${c.title} • Ao Vivo`, subtitle:'Evento com horário marcado · ranking em tempo real',
    sponsor:i===0?'Marca VIBRA Demo':'Comunidade VIBRA',
    startsAt:new Date(now+(5+i*3)*60000).toISOString(),
    endsAt:new Date(now+(17+i*3)*60000).toISOString(),
    status:'scheduled', createdAt:new Date().toISOString(),
    questions:c.questions.map(q=>({id:q.id,q:q.q,a:q.a,c:q.c}))
  }));
  write(d);
}
function liveStatus(e){const n=Date.now(),s=Date.parse(e.startsAt),x=Date.parse(e.endsAt);return n<s?'scheduled':n<x?'live':'ended'}
function eventView(d,e,uid){
  const parts=d.eventParticipants.filter(x=>x.eventId===e.id);
  const scores=new Map();
  for(const a of d.eventAnswers.filter(x=>x.eventId===e.id)) scores.set(a.userId,(scores.get(a.userId)||0)+a.points);
  const leaderboard=[...scores.entries()].map(([userId,points])=>({user:safeUser(d.users.find(u=>u.id===userId)),points,answers:d.eventAnswers.filter(x=>x.eventId===e.id&&x.userId===userId).length})).sort((a,b)=>b.points-a.points).slice(0,20);
  return {...e,status:liveStatus(e),participants:parts.length,joined:parts.some(x=>x.userId===uid),leaderboard,currentQuestion:Math.max(0,Math.min(e.questions.length-1,Math.floor((Date.now()-Date.parse(e.startsAt))/120000)))};
}
app.get('/api/live-events',auth,(req,res)=>{const d=read();ensureLiveEvents(d);res.json({events:d.liveEvents.map(e=>eventView(d,e,req.user.id))})});
app.get('/api/live-events/:id',auth,(req,res)=>{const d=read();ensureLiveEvents(d);const e=d.liveEvents.find(x=>x.id===req.params.id);if(!e)return res.status(404).json({error:'Evento não encontrado.'});const v=eventView(d,e,req.user.id);res.json({event:{...v,questions:e.questions.map(({id,q,a})=>({id,q,a}))}})});
app.post('/api/live-events/:id/join',auth,(req,res)=>{const d=read();ensureLiveEvents(d);const e=d.liveEvents.find(x=>x.id===req.params.id);if(!e)return res.status(404).json({error:'Evento não encontrado.'});let p=d.eventParticipants.find(x=>x.eventId===e.id&&x.userId===req.user.id);if(!p){p={id:id(),eventId:e.id,userId:req.user.id,joinedAt:new Date().toISOString()};d.eventParticipants.push(p);write(d)}res.json({joined:true})});
app.post('/api/live-events/:id/answer',auth,(req,res)=>{const d=read();ensureLiveEvents(d);const e=d.liveEvents.find(x=>x.id===req.params.id);if(!e)return res.status(404).json({error:'Evento não encontrado.'});const status=liveStatus(e);if(status!=='live')return res.status(400).json({error:status==='scheduled'?'O evento ainda não começou.':'O evento já terminou.'});if(!d.eventParticipants.some(x=>x.eventId===e.id&&x.userId===req.user.id))return res.status(400).json({error:'Entra primeiro no evento.'});const qIndex=Number(req.body.questionIndex);const answer=Number(req.body.answer);if(!Number.isInteger(qIndex)||qIndex<0||qIndex>=e.questions.length)return res.status(400).json({error:'Pergunta inválida.'});if(d.eventAnswers.some(x=>x.eventId===e.id&&x.userId===req.user.id&&x.questionIndex===qIndex))return res.status(400).json({error:'Já respondeste a esta pergunta.'});const q=e.questions[qIndex];const correct=answer===q.c;const row={id:id(),eventId:e.id,userId:req.user.id,questionIndex:qIndex,answer,correct,points:correct?100:0,createdAt:new Date().toISOString()};d.eventAnswers.push(row);write(d);const v=eventView(d,e,req.user.id);res.json({correct,points:row.points,leaderboard:v.leaderboard})});
app.get('/api/live-events/:id/leaderboard',auth,(req,res)=>{const d=read();ensureLiveEvents(d);const e=d.liveEvents.find(x=>x.id===req.params.id);if(!e)return res.status(404).json({error:'Evento não encontrado.'});res.json({status:liveStatus(e),leaderboard:eventView(d,e,req.user.id).leaderboard})});
app.get('/api/communities/:id/competitions',auth,(req,res)=>{
  const d=read(); ensureCommunities(d); ensureCompetitions(d);
  const list=d.competitions.filter(x=>x.communityId===req.params.id).map(c=>{const entries=d.competitionEntries.filter(e=>e.competitionId===c.id);return {id:c.id,communityId:c.communityId,title:c.title,subtitle:c.subtitle,status:c.status,startsAt:c.startsAt,endsAt:c.endsAt,participants:new Set(entries.map(e=>e.userId)).size,leaderboard:entries.sort((a,b)=>b.points-a.points).slice(0,5).map(e=>({user:safeUser(d.users.find(u=>u.id===e.userId)),points:e.points,score:e.score}))};});
  res.json({competitions:list});
});
app.get('/api/competitions/:id',auth,(req,res)=>{
  const d=read(); ensureCompetitions(d); const c=d.competitions.find(x=>x.id===req.params.id); if(!c)return res.status(404).json({error:'Competição não encontrada.'});
  const entries=d.competitionEntries.filter(e=>e.competitionId===c.id); const mine=entries.find(e=>e.userId===req.user.id); const leaderboard=entries.sort((a,b)=>b.points-a.points).map(e=>({user:safeUser(d.users.find(u=>u.id===e.userId)),points:e.points,score:e.score,createdAt:e.createdAt})).slice(0,50);
  res.json({competition:{...c,questions:c.questions.map(({id,q,a})=>({id,q,a})),participants:new Set(entries.map(e=>e.userId)).size},joined:!!mine,submitted:!!mine,leaderboard});
});
app.post('/api/competitions/:id/join',auth,(req,res)=>{
  const d=read(); ensureCompetitions(d); const c=d.competitions.find(x=>x.id===req.params.id); if(!c)return res.status(404).json({error:'Competição não encontrada.'});
  let e=d.competitionEntries.find(x=>x.competitionId===c.id&&x.userId===req.user.id); if(!e){e={id:id(),competitionId:c.id,userId:req.user.id,score:0,points:0,createdAt:new Date().toISOString()};d.competitionEntries.push(e);write(d)}
  res.json({joined:true,entry:e});
});
app.post('/api/competitions/:id/submit',auth,(req,res)=>{
  const d=read(); ensureCompetitions(d); const c=d.competitions.find(x=>x.id===req.params.id); if(!c)return res.status(404).json({error:'Competição não encontrada.'});
  let e=d.competitionEntries.find(x=>x.competitionId===c.id&&x.userId===req.user.id); if(!e){e={id:id(),competitionId:c.id,userId:req.user.id,score:0,points:0,createdAt:new Date().toISOString()};d.competitionEntries.push(e)}
  const answers=Array.isArray(req.body.answers)?req.body.answers:[]; let score=0; c.questions.forEach((q,i)=>{if(Number(answers[i])===q.c)score++}); e.score=score; e.points=score*100+(score===c.questions.length?200:0); e.updatedAt=new Date().toISOString(); write(d);
  const rank=d.competitionEntries.filter(x=>x.competitionId===c.id).sort((a,b)=>b.points-a.points).findIndex(x=>x.userId===req.user.id)+1;
  res.json({score,total:c.questions.length,points:e.points,rank,leaderboard:d.competitionEntries.filter(x=>x.competitionId===c.id).sort((a,b)=>b.points-a.points).slice(0,10).map(x=>({user:safeUser(d.users.find(u=>u.id===x.userId)),score:x.score,points:x.points}))});
});

app.get('/api/challenges/daily',auth,(req,res)=>res.json({title:'Desafio do Dia',questions:questions.map(({q,a})=>({q,a})),total:questions.length}));
app.post('/api/challenges/submit',auth,(req,res)=>{const answers=Array.isArray(req.body.answers)?req.body.answers:[];let score=0;questions.forEach((x,i)=>{if(Number(answers[i])===x.c)score++});const points=score*100+(score===10?500:0);const d=read();const result={id:id(),userId:req.user.id,score,points,createdAt:new Date().toISOString()};d.challengeResults.push(result);write(d);res.json({score,points,total:questions.length,message:score>=8?'Excelente! 🔥':score>=5?'Boa! Continua a treinar.':'Boa tentativa! Volta amanhã.'});});
app.get('/api/challenges/ranking',auth,(req,res)=>{const d=read();const map=new Map();for(const r of d.challengeResults)map.set(r.userId,(map.get(r.userId)||0)+r.points);const ranking=[...map.entries()].map(([userId,points])=>({user:safeUser(d.users.find(u=>u.id===userId)),points})).sort((a,b)=>b.points-a.points).slice(0,50);res.json({ranking});});


// --- VIBRA Smart Notifications + Event Calendar v1.7 ---
function ensureEventReminders(d){ d.eventReminders ||= []; }
function reminderView(d,r){ const e=d.liveEvents.find(x=>x.id===r.eventId); return e?{...r,event:{id:e.id,title:e.title,communityId:e.communityId,startsAt:e.startsAt,endsAt:e.endsAt,status:liveStatus(e),sponsor:e.sponsor}}:null; }
app.get('/api/event-calendar',auth,(req,res)=>{
 const d=read(); ensureLiveEvents(d); ensureEventReminders(d);
 const from=Date.now()-24*3600000, to=Date.now()+30*24*3600000;
 const events=d.liveEvents.filter(e=>Date.parse(e.endsAt)>=from&&Date.parse(e.startsAt)<=to).sort((a,b)=>Date.parse(a.startsAt)-Date.parse(b.startsAt)).map(e=>({...eventView(d,e,req.user.id),reminder: d.eventReminders.some(r=>r.eventId===e.id&&r.userId===req.user.id)}));
 res.json({events});
});
app.post('/api/live-events/:id/reminder',auth,(req,res)=>{
 const d=read(); ensureLiveEvents(d); ensureEventReminders(d); const e=d.liveEvents.find(x=>x.id===req.params.id); if(!e)return res.status(404).json({error:'Evento não encontrado.'});
 const i=d.eventReminders.findIndex(r=>r.eventId===e.id&&r.userId===req.user.id);
 if(i>=0){d.eventReminders.splice(i,1);write(d);return res.json({reminder:false});}
 d.eventReminders.push({id:id(),eventId:e.id,userId:req.user.id,createdAt:new Date().toISOString()}); write(d); res.json({reminder:true});
});
app.get('/api/notifications/smart',auth,(req,res)=>{
 const d=read(); ensureLiveEvents(d); ensureEventReminders(d); const now=Date.now();
 const reminders=d.eventReminders.filter(r=>r.userId===req.user.id).map(r=>{const e=d.liveEvents.find(x=>x.id===r.eventId);if(!e)return null;const mins=Math.round((Date.parse(e.startsAt)-now)/60000);return {eventId:e.id,title:e.title,startsAt:e.startsAt,minutesUntil:mins,status:liveStatus(e),sponsor:e.sponsor}}).filter(Boolean).filter(x=>x.status!=='ended'&&x.minutesUntil<=1440).sort((a,b)=>a.minutesUntil-b.minutesUntil);
 const recent=d.notifications.filter(n=>n.userId===req.user.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,20);
 res.json({reminders,recent});
});
app.post('/api/notifications/smart/check',auth,(req,res)=>{
 const d=read(); ensureLiveEvents(d); ensureEventReminders(d); const now=Date.now(); let created=0;
 for(const r of d.eventReminders.filter(x=>x.userId===req.user.id)){
  const e=d.liveEvents.find(x=>x.id===r.eventId); if(!e)continue; const mins=(Date.parse(e.startsAt)-now)/60000;
  const windows=[30,10,0]; const bucket=mins<=0?'start':mins<=10?'10':mins<=30?'30':null; if(!bucket)continue;
  const key=`event_reminder:${e.id}:${bucket}`;
  if(d.notifications.some(n=>n.userId===req.user.id&&n.type==='smart_event'&&n.meta?.key===key))continue;
  notify(d,req.user.id,'smart_event',mins>0?`⏰ ${e.title} começa em ${Math.max(1,Math.ceil(mins))} min.`:`🔴 ${e.title} começou agora!`,{key,eventId:e.id,startsAt:e.startsAt}); created++;
 }
 write(d); res.json({created});
});

// --- VIBRA Safety, Moderation & Privacy v1.9 ---
const allowedReportTypes=['post','comment','user','message','campaign'];
app.get('/api/privacy',auth,(req,res)=>{const d=read();res.json({settings:privacyFor(d,req.user.id)});write(d)});
app.patch('/api/privacy',auth,(req,res)=>{const d=read();const p=privacyFor(d,req.user.id);if(req.body.profile!==undefined&&!['public','followers'].includes(req.body.profile))return res.status(400).json({error:'Privacidade de perfil inválida.'});if(req.body.messages!==undefined&&!['everyone','followers','nobody'].includes(req.body.messages))return res.status(400).json({error:'Privacidade de mensagens inválida.'});if(req.body.profile!==undefined)p.profile=req.body.profile;if(req.body.messages!==undefined)p.messages=req.body.messages;write(d);res.json({settings:p})});
app.get('/api/blocks',auth,(req,res)=>{const d=read();const rows=d.blocks.filter(x=>x.blockerId===req.user.id).map(x=>safeUser(d.users.find(u=>u.id===x.blockedId))).filter(Boolean);res.json({users:rows})});
app.post('/api/users/:id/block',auth,(req,res)=>{const d=read();const target=d.users.find(u=>u.id===req.params.id);if(!target)return res.status(404).json({error:'Utilizador não encontrado.'});if(target.id===req.user.id)return res.status(400).json({error:'Não podes bloquear a tua própria conta.'});const i=d.blocks.findIndex(x=>x.blockerId===req.user.id&&x.blockedId===target.id);if(i>=0)d.blocks.splice(i,1);else d.blocks.push({id:id(),blockerId:req.user.id,blockedId:target.id,createdAt:new Date().toISOString()});write(d);res.json({blocked:i<0})});
app.post('/api/reports',auth,(req,res)=>{const {type,targetId,reason=''}=req.body||{};if(!allowedReportTypes.includes(type)||!targetId||!String(reason).trim())return res.status(400).json({error:'Tipo, conteúdo e motivo são obrigatórios.'});const d=read();const valid= type==='post'?d.posts.some(x=>x.id===targetId): type==='comment'?d.comments.some(x=>x.id===targetId): type==='user'?d.users.some(x=>x.id===targetId): type==='message'?d.messages.some(x=>x.id===targetId):d.campaigns.some(x=>x.id===targetId);if(!valid)return res.status(404).json({error:'Conteúdo não encontrado.'});if(d.reports.some(x=>x.reporterId===req.user.id&&x.type===type&&x.targetId===targetId&&x.status==='open'))return res.json({ok:true,duplicate:true});const r={id:id(),reporterId:req.user.id,type,targetId,reason:String(reason).trim().slice(0,500),status:'open',createdAt:new Date().toISOString()};d.reports.push(r);write(d);res.status(201).json({ok:true,reportId:r.id})});
app.get('/api/moderation/mine',auth,(req,res)=>{const d=read();res.json({reports:d.reports.filter(x=>x.reporterId===req.user.id).map(x=>({id:x.id,type:x.type,targetId:x.targetId,reason:x.reason,status:x.status,createdAt:x.createdAt}))})});

app.use((req,res,next)=>{if(req.method==='GET'&&!req.path.startsWith('/api'))return res.sendFile(path.join(__dirname,'public','index.html'));next()});
initPersistence().then(()=>{
  


vibraDB.initDb().then(() => {
  console.log("VIBRA database mode:", vibraDB.status().mode);
}).catch(err => {
  console.error("VIBRA database initialization failed:", err);
});

app.get("/api/db-status", async (req, res) => {
  try {
    res.json(vibraDB.status());
  } catch (err) {
    res.status(500).json({ error: "database_status_failed" });
  }
});

app.listen(PORT,()=>console.log(`VIBRA v2.1 em http://localhost:${PORT}`));
}).catch(err=>{
  console.error('Falha ao inicializar persistência:',err);
  process.exit(1);
});

