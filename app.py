import os, hashlib, secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from jose import jwt, JWTError
from sqlalchemy import create_engine, String, Integer, Text, DateTime, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

DATABASE_URL=os.getenv("DATABASE_URL","sqlite:///./jeztech_learning.db")
if DATABASE_URL.startswith("postgres://"): DATABASE_URL=DATABASE_URL.replace("postgres://","postgresql+psycopg://",1)
if DATABASE_URL.startswith("postgresql://") and "+" not in DATABASE_URL.split("://")[0]: DATABASE_URL=DATABASE_URL.replace("postgresql://","postgresql+psycopg://",1)
engine=create_engine(DATABASE_URL,connect_args={"check_same_thread":False} if DATABASE_URL.startswith("sqlite") else {},pool_pre_ping=True)
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False)
class Base(DeclarativeBase): pass
class User(Base):
    __tablename__="users"
    id:Mapped[int]=mapped_column(primary_key=True); name:Mapped[str]=mapped_column(String(160)); email:Mapped[str]=mapped_column(String(200),unique=True,index=True); password_hash:Mapped[str]=mapped_column(String(300)); role:Mapped[str]=mapped_column(String(20)); class_name:Mapped[str]=mapped_column(String(80),default="")
class Record(Base):
    __tablename__="records"
    id:Mapped[int]=mapped_column(primary_key=True); kind:Mapped[str]=mapped_column(String(40),index=True); title:Mapped[str]=mapped_column(String(240)); body:Mapped[str]=mapped_column(Text,default=""); subject:Mapped[str]=mapped_column(String(120),default=""); owner_id:Mapped[int]=mapped_column(Integer,default=0); status:Mapped[str]=mapped_column(String(40),default="published"); created_at:Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
class Submission(Base):
    __tablename__="submissions"
    id:Mapped[int]=mapped_column(primary_key=True); record_id:Mapped[int]=mapped_column(Integer,index=True); student_id:Mapped[int]=mapped_column(Integer,index=True); content:Mapped[str]=mapped_column(Text,default=""); score:Mapped[Optional[int]]=mapped_column(Integer,nullable=True); feedback:Mapped[str]=mapped_column(Text,default=""); created_at:Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
Base.metadata.create_all(engine)
app=FastAPI(title="JEZTECH Learning API",version="1.0.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=False,allow_methods=["*"],allow_headers=["*"])
SECRET=os.getenv("JWT_SECRET","CHANGE_THIS_SECRET_BEFORE_PRODUCTION")
def db():
    s=SessionLocal()
    try: yield s
    finally: s.close()
def ph(p,salt=None):
    salt=salt or secrets.token_hex(16); return salt+"$"+hashlib.pbkdf2_hmac("sha256",p.encode(),salt.encode(),240000).hex()
def verify(p,h):
    try: salt,digest=h.split("$",1); return secrets.compare_digest(ph(p,salt).split("$",1)[1],digest)
    except Exception: return False
def token(u): return jwt.encode({"sub":str(u.id),"role":u.role,"exp":datetime.now(timezone.utc)+timedelta(hours=12)},SECRET,algorithm="HS256")
def current(authorization:str=Header(default=""),s:Session=Depends(db)):
    if not authorization.startswith("Bearer "): raise HTTPException(401,"Sign in required")
    try: data=jwt.decode(authorization[7:],SECRET,algorithms=["HS256"]); u=s.get(User,int(data["sub"]))
    except (JWTError,ValueError,KeyError): u=None
    if not u: raise HTTPException(401,"Session expired")
    return u
def allow(*roles):
    def check(u:User=Depends(current)):
        if u.role not in roles: raise HTTPException(403,"Your account cannot perform this action")
        return u
    return check
@app.on_event("startup")
def seed():
    with SessionLocal() as s:
        email=os.getenv("ADMIN_EMAIL","admin@jeztech.local").lower()
        if not s.query(User).filter_by(email=email).first():
            s.add(User(name="JEZTECH Administrator",email=email,password_hash=ph(os.getenv("ADMIN_PASSWORD","ChangeMe123!")),role="admin")); s.commit()
@app.get("/health")
def health(): return {"status":"ok","service":"JEZTECH Learning"}
@app.post("/api/auth/login")
def login(data:dict,s:Session=Depends(db)):
    u=s.query(User).filter_by(email=str(data.get("email","")).lower()).first()
    if not u or not verify(str(data.get("password","")),u.password_hash): raise HTTPException(401,"Invalid email or password")
    return {"token":token(u),"user":{"id":u.id,"name":u.name,"email":u.email,"role":u.role,"class_name":u.class_name}}
@app.post("/api/users")
def create_user(data:dict,u:User=Depends(allow("admin")),s:Session=Depends(db)):
    role=data.get("role")
    if role not in ("admin","teacher","student","parent"): raise HTTPException(400,"Invalid role")
    email=str(data.get("email","")).lower()
    if s.query(User).filter_by(email=email).first(): raise HTTPException(409,"Email already exists")
    x=User(name=data["name"],email=email,password_hash=ph(data["password"]),role=role,class_name=data.get("class_name","")); s.add(x); s.commit(); return {"id":x.id,"email":x.email}
@app.get("/api/users")
def users(u:User=Depends(allow("admin","teacher")),s:Session=Depends(db)):
    return [{"id":x.id,"name":x.name,"email":x.email,"role":x.role,"class_name":x.class_name} for x in s.query(User).all()]
@app.get("/api/me")
def me(u:User=Depends(current)): return {"id":u.id,"name":u.name,"email":u.email,"role":u.role,"class_name":u.class_name}
@app.get("/api/records")
def records(kind:str="",u:User=Depends(current),s:Session=Depends(db)):
    q=s.query(Record)
    if kind: q=q.filter_by(kind=kind)
    return [{"id":x.id,"kind":x.kind,"title":x.title,"body":x.body,"subject":x.subject,"status":x.status,"owner_id":x.owner_id,"created_at":x.created_at.isoformat()} for x in q.order_by(Record.created_at.desc()).all()]
@app.post("/api/records")
def create_record(data:dict,u:User=Depends(allow("admin","teacher")),s:Session=Depends(db)):
    kind=data.get("kind")
    if kind not in ("course","lesson","assignment","exam","lab","announcement","message"): raise HTTPException(400,"Unsupported content type")
    x=Record(kind=kind,title=data["title"],body=data.get("body",""),subject=data.get("subject",""),owner_id=u.id,status=data.get("status","published")); s.add(x); s.commit(); s.refresh(x); return {"id":x.id}
@app.put("/api/records/{rid}")
def edit_record(rid:int,data:dict,u:User=Depends(allow("admin","teacher")),s:Session=Depends(db)):
    x=s.get(Record,rid)
    if not x: raise HTTPException(404,"Not found")
    if u.role!="admin" and x.owner_id!=u.id: raise HTTPException(403,"Only the author or administrator can edit this item")
    for k in ("title","body","subject","status"):
        if k in data: setattr(x,k,data[k])
    s.commit(); return {"saved":True}
@app.delete("/api/records/{rid}")
def delete_record(rid:int,u:User=Depends(allow("admin","teacher")),s:Session=Depends(db)):
    x=s.get(Record,rid)
    if not x: raise HTTPException(404,"Not found")
    if u.role!="admin" and x.owner_id!=u.id: raise HTTPException(403,"Only the author or administrator can delete this item")
    s.delete(x); s.commit(); return {"deleted":True}
@app.post("/api/submissions")
def submit(data:dict,u:User=Depends(allow("student")),s:Session=Depends(db)):
    x=Submission(record_id=int(data["record_id"]),student_id=u.id,content=data.get("content","")); s.add(x); s.commit(); return {"submitted":True,"id":x.id}
@app.get("/api/submissions")
def submissions(u:User=Depends(allow("admin","teacher")),s:Session=Depends(db)):
    return [{"id":x.id,"record_id":x.record_id,"student_id":x.student_id,"content":x.content,"score":x.score,"feedback":x.feedback} for x in s.query(Submission).all()]
@app.put("/api/submissions/{sid}/grade")
def grade(sid:int,data:dict,u:User=Depends(allow("admin","teacher")),s:Session=Depends(db)):
    x=s.get(Submission,sid)
    if not x: raise HTTPException(404,"Submission not found")
    x.score=int(data["score"]); x.feedback=data.get("feedback",""); s.commit(); return {"graded":True}
@app.get("/api/dashboard")
def dashboard(u:User=Depends(current),s:Session=Depends(db)):
    return {"role":u.role,"courses":s.query(Record).filter_by(kind="course").count(),"lessons":s.query(Record).filter_by(kind="lesson").count(),"assignments":s.query(Record).filter_by(kind="assignment").count(),"exams":s.query(Record).filter_by(kind="exam").count(),"submissions":s.query(Submission).count()}
@app.get("/")
def home(): return FileResponse("static/index.html")
app.mount("/static",StaticFiles(directory="static"),name="static")
