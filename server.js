const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'bingo-state.json');
if (!ADMIN_PASSWORD) {
  console.error('ADMIN_PASSWORD environment variable is required.');
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true });

function makeCard() {
  const cols = [];
  for (let c=0;c<5;c++) {
    const min=c*15+1, max=c*15+15, a=[];
    while(a.length<5){const n=Math.floor(Math.random()*(max-min+1))+min;if(!a.includes(n))a.push(n);}
    cols.push(a);
  }
  return Array.from({length:5},(_,r)=>Array.from({length:5},(_,c)=>r===2&&c===2?0:cols[c][r]));
}
const defaultState = () => ({
  drawn: [], players: [], chat: [],
  prizes: [
    {rank:'1位',icon:'🏆',name:'特賞 クリスマスプレゼント'},
    {rank:'2位',icon:'🎁',name:'お楽しみギフト'},
    {rank:'3位',icon:'🍰',name:'クリスマススイーツ'}
  ],
  currentSong:'jingle', musicOn:false, updatedAt:Date.now()
});
let state;
try { state = fs.existsSync(DATA_FILE) ? JSON.parse(fs.readFileSync(DATA_FILE,'utf8')) : defaultState(); }
catch(e) { console.error('State file invalid; starting a new event.',e); state=defaultState(); }
function save(){state.updatedAt=Date.now();const tmp=DATA_FILE+'.tmp';fs.writeFileSync(tmp,JSON.stringify(state,null,2));fs.renameSync(tmp,DATA_FILE);}
function publicState(){const copy=JSON.parse(JSON.stringify(state));copy.players=copy.players.map(({name,status})=>({name,status}));return copy;}
function sign(payload){const body=Buffer.from(JSON.stringify(payload)).toString('base64url');const sig=crypto.createHmac('sha256',SECRET).update(body).digest('base64url');return body+'.'+sig;}
function verify(token){try{const [body,sig]=String(token||'').split('.');const expected=crypto.createHmac('sha256',SECRET).update(body).digest();const actual=Buffer.from(sig,'base64url');if(actual.length!==expected.length||!crypto.timingSafeEqual(actual,expected))return null;const p=JSON.parse(Buffer.from(body,'base64url').toString());if(p.exp<Date.now())return null;return p;}catch{return null;}}
function isAdmin(token){const p=verify(token);return !!p&&p.role==='admin';}
function safeName(s){return String(s||'').trim().replace(/[<>]/g,'').slice(0,20);}
function escapeText(s){return String(s||'').slice(0,200);}
function bingoStatus(card,drawn){const lines=[];for(let r=0;r<5;r++)lines.push(card[r].map(n=>n===0||drawn.includes(n)));for(let c=0;c<5;c++)lines.push(card.map(row=>row[c]===0||drawn.includes(row[c])));lines.push([0,1,2,3,4].map(i=>card[i][i]===0||drawn.includes(card[i][i])));lines.push([0,1,2,3,4].map(i=>card[i][4-i]===0||drawn.includes(card[i][4-i])));if(lines.some(a=>a.every(Boolean)))return 'BINGO';for(const line of lines){if(line.filter(Boolean).length===4)return 'リーチ';}return '参加中';}
const app=express();
app.disable('x-powered-by');
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');next();});
app.use(express.static(path.join(__dirname,'public'),{extensions:['html']}));
app.get('/health',(req,res)=>res.json({ok:true,players:state.players.length}));
const server=http.createServer(app);
const io=new Server(server,{cors:{origin:false},maxHttpBufferSize:1e5});
const rate=new Map();
function rateOk(id){const now=Date.now(),a=(rate.get(id)||[]).filter(t=>now-t<10000);if(a.length>=12)return false;a.push(now);rate.set(id,a);return true;}
function emitState(){io.emit('state:update',publicState());}
function ack(cb,obj){if(typeof cb==='function')cb(obj);}
io.on('connection',socket=>{
  socket.on('state:get',(_,cb)=>ack(cb,publicState()));
  socket.on('participant:join',(data,cb)=>{
    if(!rateOk(socket.id))return ack(cb,{ok:false,error:'操作が多すぎます。少し待ってください。'});
    const name=safeName(data?.name);if(!name)return ack(cb,{ok:false,error:'名前を入力してください。'});
    let p=state.players.find(x=>x.id===data?.playerId);
    if(!p){
      if(state.players.length>=30)return ack(cb,{ok:false,error:'参加人数の上限（30人）に達しました。主催者にお知らせください。'});
      p={id:crypto.randomUUID(),name,card:makeCard(),status:'参加中',joinedAt:Date.now()};
      state.players.push(p);save();emitState();
    }else{
      p.name=name;save();emitState();
    }
    socket.data.playerId=p.id;
    ack(cb,{ok:true,player:{id:p.id,name:p.name,card:p.card},state:publicState()});
  });
  socket.on('participant:resume',(data,cb)=>{
    const p=state.players.find(x=>x.id===data?.playerId);
    if(!p)return ack(cb,{ok:false});
    socket.data.playerId=p.id;ack(cb,{ok:true,player:{id:p.id,name:p.name,card:p.card},state:publicState()});
  });
  socket.on('admin:login',(data,cb)=>{
    const pass=String(data?.password||'');
    if(!crypto.timingSafeEqual(Buffer.from(pass.padEnd(128,'\0').slice(0,128)),Buffer.from(ADMIN_PASSWORD.padEnd(128,'\0').slice(0,128))))return ack(cb,{ok:false,error:'合言葉が違います。もう一度入力してください。'});
    const token=sign({role:'admin',exp:Date.now()+12*60*60*1000});
    socket.data.admin=true;ack(cb,{ok:true,token,state:publicState()});
  });
  socket.on('admin:resume',(data,cb)=>{
    if(!isAdmin(data?.token))return ack(cb,{ok:false});
    socket.data.admin=true;ack(cb,{ok:true,state:publicState()});
  });
  socket.on('admin:draw',async(data,cb)=>{
    if(!isAdmin(data?.token))return ack(cb,{ok:false,error:'管理者としてログインしてください。'});
    if(state.drawn.length>=75)return ack(cb,{ok:false,error:'すべての数字が抽選済みです。'});
    if(state.drawing)return ack(cb,{ok:false,error:'抽選中です。'});
    state.drawing=true;io.emit('draw:start');ack(cb,{ok:true});
    await new Promise(r=>setTimeout(r,5200));
    const remaining=Array.from({length:75},(_,i)=>i+1).filter(n=>!state.drawn.includes(n));
    const number=remaining[Math.floor(Math.random()*remaining.length)];
    state.drawn.push(number);state.drawing=false;
    const claims=[];
    for(const p of state.players){
      const status=bingoStatus(p.card,state.drawn);
      if(status!==p.status){p.status=status;if(status==='BINGO'||status==='リーチ')claims.push({name:p.name,status});}
    }
    save();
    io.emit('draw:result',{number,drawn:state.drawn,claims});
    claims.forEach(c=>io.emit('claim:new',c));
    emitState();
  });
  socket.on('admin:reset',(data,cb)=>{
    if(!isAdmin(data?.token))return ack(cb,{ok:false,error:'管理者としてログインしてください。'});
    state=defaultState();save();io.emit('participant:removed');emitState();ack(cb,{ok:true});
  });
  socket.on('admin:prize:add',(data,cb)=>{
    if(!isAdmin(data?.token))return ack(cb,{ok:false,error:'管理者としてログインしてください。'});
    const p=data?.prize||{},rank=String(p.rank||'').slice(0,12),icon=String(p.icon||'🎁').slice(0,8),name=String(p.name||'').trim().slice(0,80);
    if(!rank||!name)return ack(cb,{ok:false,error:'順位と景品名を入力してください。'});
    const idx=state.prizes.findIndex(x=>x.rank===rank),item={rank,icon,name};if(idx>=0)state.prizes[idx]=item;else state.prizes.push(item);save();emitState();ack(cb,{ok:true});
  });
  socket.on('admin:prize:delete',(data,cb)=>{
    if(!isAdmin(data?.token))return ack(cb,{ok:false,error:'管理者としてログインしてください。'});
    const i=Number(data?.index);if(!Number.isInteger(i)||i<0||i>=state.prizes.length)return ack(cb,{ok:false,error:'景品が見つかりません。'});
    state.prizes.splice(i,1);save();emitState();ack(cb,{ok:true});
  });
  socket.on('admin:music',(data,cb)=>{
    if(!isAdmin(data?.token))return ack(cb,{ok:false,error:'BGMの操作は管理者のみです。'});
    const song=['jingle','wewish','silent'].includes(data?.song)?data.song:state.currentSong;
    state.currentSong=song;state.musicOn=!!data?.playing;save();io.emit('music:update',{song,playing:state.musicOn});ack(cb,{ok:true});
  });
  socket.on('chat:send',(data,cb)=>{
    if(!rateOk(socket.id))return;
    const p=state.players.find(x=>x.id===socket.data.playerId);
    const admin=isAdmin(data?.token);
    const text=escapeText(data?.text).trim();if((!p&&!admin)||!text)return;
    const m={id:crypto.randomUUID(),name:admin?'主催者':p.name,text,at:Date.now()};state.chat.push(m);state.chat=state.chat.slice(-100);save();io.emit('chat:new',m);ack(cb,{ok:true});
  });
  socket.on('disconnect',()=>{});
});
server.listen(PORT,'0.0.0.0',()=>console.log(`Katakuri Bingo listening on ${PORT}`));
