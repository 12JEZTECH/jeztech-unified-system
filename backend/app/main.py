import os, uuid, base64
from datetime import datetime, timedelta, timezone
from typing import Optional
import requests
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, DateTime, ForeignKey, Text, Boolean, Integer, or_
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt, JWTError

URL=os.getenv("DATABASE_URL","sqlite:///./jeztech_learning.db")
if URL.startswith("postgres://"): URL=URL.replace("postgres://","postgresql://",1)
engine=create_engine(URL,connect_args={"check_same_thread":False} if URL.startswith("sqlite") else {},pool_pre_ping=True)
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False)
SECRET=os.getenv("JWT_SECRET_KEY")
if not SECRET: raise RuntimeError("Set JWT_SECRET_KEY")
pwd=CryptContext(schemes=["bcrypt"],deprecated="auto"); oauth=OAuth2PasswordBearer(tokenUrl="/auth/token")
def now(): return datetime.now(timezone.utc)
class Base(DeclarativeBase): pass
class User(Base):
 __tablename__="users"
 id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
 email:Mapped[str]=mapped_column(String(255),unique=True,index=True); full_name:Mapped[str]=mapped_column(String(180))
 password_hash:Mapped[str]=mapped_column(String(255)); role:Mapped[str]=mapped_column(String(20),index=True)
 class_name:Mapped[Optional[str]]=mapped_column(String(80),nullable=True); curriculum:Mapped[Optional[str]]=mapped_column(String(20),nullable=True)
 admission_no:Mapped[Optional[str]]=mapped_column(String(80),nullable=True,index=True); phone:Mapped[Optional[str]]=mapped_column(String(20),nullable=True)
 active:Mapped[bool]=mapped_column(Boolean,default=True); access_expires_at:Mapped[Optional[datetime]]=mapped_column(DateTime(timezone=True),nullable=True)
class Course(Base):
 __tablename__="courses"
 id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
 title:Mapped[str]=mapped_column(String(200)); subject:Mapped[str]=mapped_column(String(100)); curriculum:Mapped[str]=mapped_column(String(20))
 grade_form:Mapped[str]=mapped_column(String(80)); teacher_id:Mapped[str]=mapped_column(ForeignKey("users.id")); published:Mapped[bool]=mapped_column(Boolean,default=False)
class Lesson(Base):
 __tablename__="lessons"
 id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
 course_id:Mapped[str]=mapped_column(ForeignKey("courses.id"),index=True); title:Mapped[str]=mapped_column(String(200))
 body:Mapped[str]=mapped_column(Text); resource_url:Mapped[Optional[str]]=mapped_column(String(500),nullable=True); published:Mapped[bool]=mapped_column(Boolean,default=False)
class Payment(Base):
 __tablename__="payments"
 id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
 user_id:Mapped[str]=mapped_column(ForeignKey("users.id"),index=True); amount:Mapped[int]=mapped_column(Integer)
 phone:Mapped[str]=mapped_column(String(20)); checkout_id:Mapped[str]=mapped_column(String(100),unique=True,index=True)
 receipt:Mapped[Optional[str]]=mapped_column(String(40),nullable=True); status:Mapped[str]=mapped_column(String(20),default="pending")
class Setting(Base):
 __tablename__="settings"
 key:Mapped[str]=mapped_column(String(80),primary_key=True); value:Mapped[str]=mapped_column(String(100))
Base.metadata.create_all(engine)
app=FastAPI(title="JEZTECH Learning API",version="2.0")
app.add_middleware(CORSMiddleware,allow_origins=os.getenv("CORS_ORIGINS","http://localhost:5500").split(","),allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
def dbdep():
 d=SessionLocal()
 try: yield d
 finally: d.close()
def user(token:str=Depends(oauth),d:Session=Depends(dbdep)):
 try: uid=jwt.decode(token,SECRET,algorithms=["HS256"]).get("sub")
 except JWTError: raise HTTPException(401,"Please sign in again")
 u=d.get(User,uid)
 if not u or not u.active: raise HTTPException(401,"Account disabled")
 return u
def roles(*allowed):
 def check(u:User=Depends(user)):
  if u.role not in allowed: raise HTTPException(403,"Not authorised")
  return u
 return check
def access(u):
 expiry=u.access_expires_at
 if expiry and expiry.tzinfo is None: expiry=expiry.replace(tzinfo=timezone.utc)
 if not expiry or expiry<=now(): raise HTTPException(402,"Tuition expired. Pay through M-Pesa to restore learning access.")
class Register(BaseModel):
 full_name:str; email:str; password:str=Field(min_length=6); admission_no:str; phone:Optional[str]=None
 curriculum:str; class_name:str
class UserCreate(Register):
 role:str="teacher"
class CourseIn(BaseModel):
 title:str; subject:str; curriculum:str; grade_form:str
class LessonIn(BaseModel):
 title:str; body:str; resource_url:Optional[str]=None; published:bool=False
class STK(BaseModel):
 phone:str; amount:int=Field(gt=0)
class SettingsIn(BaseModel):
 tuition_amount:int=Field(gt=0); access_days:int=Field(ge=1,le=365)
class AccessIn(BaseModel):
 days:int=Field(default=30,ge=0,le=730); active:Optional[bool]=None; expires_at:Optional[datetime]=None
@app.get("/health")
def health(): return {"status":"ok","service":"JEZTECH Learning API"}
@app.post("/auth/register")
def register(p:Register,d:Session=Depends(dbdep)):
 if p.curriculum not in ("CBC","8-4-4"): raise HTTPException(400,"Choose CBC or 8-4-4")
 if d.query(User).filter(or_(User.email==p.email.lower(),User.admission_no==p.admission_no)).first(): raise HTTPException(409,"Account already exists")
 d.add(User(email=p.email.lower(),full_name=p.full_name,password_hash=pwd.hash(p.password),role="student",admission_no=p.admission_no,phone=p.phone,curriculum=p.curriculum,class_name=p.class_name,active=False)); d.commit()
 return {"status":"pending_admin_activation","message":"Registration request sent. There is no registration fee."}
@app.post("/auth/token")
def login(f:OAuth2PasswordRequestForm=Depends(),d:Session=Depends(dbdep)):
 ident=f.username.strip(); u=d.query(User).filter(or_(User.email==ident.lower(),User.admission_no==ident)).first()
 if not u or not u.active or not pwd.verify(f.password,u.password_hash): raise HTTPException(401,"Incorrect login or account not activated")
 return {"access_token":jwt.encode({"sub":u.id,"exp":now()+timedelta(hours=12)},SECRET,algorithm="HS256"),"token_type":"bearer","role":u.role}
@app.get("/me")
def me(u:User=Depends(user)):
 return {"id":u.id,"name":u.full_name,"role":u.role,"class_name":u.class_name,"curriculum":u.curriculum,"access_expires_at":u.access_expires_at.isoformat() if u.access_expires_at else None}
@app.post("/admin/users")
def create_user(p:UserCreate,d:Session=Depends(dbdep),a:User=Depends(roles("admin"))):
 if p.role not in ("teacher","student","parent"): raise HTTPException(400,"Role not allowed")
 if d.query(User).filter(or_(User.email==p.email.lower(),User.admission_no==p.admission_no)).first(): raise HTTPException(409,"User exists")
 x=User(email=p.email.lower(),full_name=p.full_name,password_hash=pwd.hash(p.password),role=p.role,admission_no=p.admission_no,phone=p.phone,curriculum=p.curriculum,class_name=p.class_name,active=True);d.add(x);d.commit()
 return {"id":x.id,"username":x.admission_no or x.email}
@app.get("/admin/users")
def users(d:Session=Depends(dbdep),a:User=Depends(roles("admin"))):
 return [{"id":x.id,"name":x.full_name,"username":x.admission_no or x.email,"role":x.role,"class_name":x.class_name,"curriculum":x.curriculum,"active":x.active,"expires_at":x.access_expires_at.isoformat() if x.access_expires_at else None} for x in d.query(User).all()]
@app.post("/admin/users/{uid}/access")
def update_access(uid:str,p:AccessIn,d:Session=Depends(dbdep),a:User=Depends(roles("admin"))):
 x=d.get(User,uid)
 if not x or x.role!="student": raise HTTPException(404,"Learner not found")
 if p.active is not None: x.active=p.active
 if p.expires_at: x.access_expires_at=p.expires_at
 elif p.days: 
  old=x.access_expires_at
  if old and old.tzinfo is None: old=old.replace(tzinfo=timezone.utc)
  x.access_expires_at=max(old,now())+timedelta(days=p.days) if old else now()+timedelta(days=p.days)
 d.commit(); return {"active":x.active,"expires_at":x.access_expires_at.isoformat() if x.access_expires_at else None}
@app.get("/admin/settings")
def settings(d:Session=Depends(dbdep),a:User=Depends(roles("admin"))):
 return {"tuition_amount":int(d.get(Setting,"tuition_amount").value) if d.get(Setting,"tuition_amount") else int(os.getenv("DEFAULT_TUITION_AMOUNT","1000")),"access_days":int(d.get(Setting,"access_days").value) if d.get(Setting,"access_days") else 30}
@app.put("/admin/settings")
def set_settings(p:SettingsIn,d:Session=Depends(dbdep),a:User=Depends(roles("admin"))):
 for k,v in [("tuition_amount",p.tuition_amount),("access_days",p.access_days)]:
  x=d.get(Setting,k)
  if x:x.value=str(v)
  else:d.add(Setting(key=k,value=str(v)))
 d.commit(); return {"saved":True}
@app.get("/payments/tuition")
def tuition(d:Session=Depends(dbdep)):
 x=d.get(Setting,"tuition_amount"); y=d.get(Setting,"access_days")
 return {"amount":int(x.value) if x else int(os.getenv("DEFAULT_TUITION_AMOUNT","1000")),"access_days":int(y.value) if y else 30}
def daraja_token():
 key=os.getenv("MPESA_CONSUMER_KEY"); secret=os.getenv("MPESA_CONSUMER_SECRET")
 if not key or not secret: raise HTTPException(503,"Daraja credentials missing")
 base="https://sandbox.safaricom.co.ke" if os.getenv("MPESA_ENV","sandbox")=="sandbox" else "https://api.safaricom.co.ke"
 try: return requests.get(base+"/oauth/v1/generate?grant_type=client_credentials",auth=(key,secret),timeout=20).json()["access_token"]
 except Exception: raise HTTPException(502,"Could not authenticate with Daraja")
@app.post("/payments/mpesa/stk-push")
def stk(p:STK,d:Session=Depends(dbdep),u:User=Depends(roles("student"))):
 amount=int(d.get(Setting,"tuition_amount").value) if d.get(Setting,"tuition_amount") else int(os.getenv("DEFAULT_TUITION_AMOUNT","1000"))
 if p.amount!=amount: raise HTTPException(400,"Amount does not match current tuition")
 phone=p.phone.replace("+","").replace(" ","")
 if phone.startswith("0"): phone="254"+phone[1:]
 if phone.startswith(("7","1")): phone="254"+phone
 if not phone.startswith("254") or len(phone)!=12 or not phone.isdigit(): raise HTTPException(400,"Enter a valid Kenyan M-Pesa number")
 shortcode=os.getenv("MPESA_SHORTCODE"); passkey=os.getenv("MPESA_PASSKEY"); callback=os.getenv("MPESA_CALLBACK_URL")
 if not all([shortcode,passkey,callback]): raise HTTPException(503,"Daraja shortcode, passkey and callback URL must be configured")
 stamp=now().astimezone(timezone(timedelta(hours=3))).strftime("%Y%m%d%H%M%S")
 password=base64.b64encode((shortcode+passkey+stamp).encode()).decode()
 base="https://sandbox.safaricom.co.ke" if os.getenv("MPESA_ENV","sandbox")=="sandbox" else "https://api.safaricom.co.ke"
 body={"BusinessShortCode":shortcode,"Password":password,"Timestamp":stamp,"TransactionType":os.getenv("MPESA_TRANSACTION_TYPE","CustomerPayBillOnline"),"Amount":amount,"PartyA":phone,"PartyB":shortcode,"PhoneNumber":phone,"CallBackURL":callback,"AccountReference":(u.admission_no or u.id)[:12],"TransactionDesc":"JEZTECH tuition"}
 try:
  r=requests.post(base+"/mpesa/stkpush/v1/processrequest",json=body,headers={"Authorization":"Bearer "+daraja_token()},timeout=30); r.raise_for_status(); result=r.json()
 except Exception: raise HTTPException(502,"STK push request failed")
 if result.get("ResponseCode")!="0": raise HTTPException(502,result.get("ResponseDescription","Daraja rejected request"))
 d.add(Payment(user_id=u.id,amount=amount,phone=phone,checkout_id=result["CheckoutRequestID"]));d.commit()
 return {"message":"STK push sent. Enter your M-Pesa PIN.","checkout_request_id":result["CheckoutRequestID"]}
@app.post("/payments/mpesa/callback")
async def callback(req:Request,d:Session=Depends(dbdep)):
 payload=await req.json(); cb=payload.get("Body",{}).get("stkCallback",{}); p=d.query(Payment).filter_by(checkout_id=cb.get("CheckoutRequestID")).first()
 if p and cb.get("ResultCode")==0 and p.status!="paid":
  meta={i.get("Name"):i.get("Value") for i in cb.get("CallbackMetadata",{}).get("Item",[])}
  if int(meta.get("Amount",0))==p.amount and meta.get("MpesaReceiptNumber"):
   p.status="paid";p.receipt=meta["MpesaReceiptNumber"];u=d.get(User,p.user_id)
   days=int(d.get(Setting,"access_days").value) if d.get(Setting,"access_days") else 30
   old=u.access_expires_at
   if old and old.tzinfo is None:old=old.replace(tzinfo=timezone.utc)
   u.access_expires_at=(max(old,now()) if old else now())+timedelta(days=days);u.active=True;d.commit()
 return {"ResultCode":0,"ResultDesc":"Accepted"}
@app.get("/courses")
def courses(d:Session=Depends(dbdep),u:User=Depends(user)):
 q=d.query(Course)
 if u.role=="teacher":q=q.filter(Course.teacher_id==u.id)
 if u.role=="student":
  access(u);q=q.filter(Course.curriculum==u.curriculum,Course.grade_form==u.class_name,Course.published==True)
 return [{"id":c.id,"title":c.title,"subject":c.subject,"curriculum":c.curriculum,"grade_form":c.grade_form} for c in q.all() if c.published or u.role in ("teacher","admin")]
@app.post("/courses")
def add_course(p:CourseIn,d:Session=Depends(dbdep),u:User=Depends(roles("teacher","admin"))):
 if p.curriculum not in ("CBC","8-4-4"):raise HTTPException(400,"Invalid curriculum")
 c=Course(**p.model_dump(),teacher_id=u.id);d.add(c);d.commit();return {"id":c.id}
@app.post("/courses/{cid}/lessons")
def add_lesson(cid:str,p:LessonIn,d:Session=Depends(dbdep),u:User=Depends(roles("teacher","admin"))):
 c=d.get(Course,cid)
 if not c or (u.role=="teacher" and c.teacher_id!=u.id):raise HTTPException(404,"Course not found")
 l=Lesson(course_id=cid,**p.model_dump());d.add(l);d.commit();return {"id":l.id}
@app.get("/courses/{cid}/lessons")
def get_lessons(cid:str,d:Session=Depends(dbdep),u:User=Depends(user)):
 c=d.get(Course,cid)
 if not c:raise HTTPException(404,"Course not found")
 if u.role=="student":
  access(u)
  if c.curriculum!=u.curriculum or c.grade_form!=u.class_name:raise HTTPException(403,"Wrong class")
 return [{"id":l.id,"title":l.title,"body":l.body,"resource_url":l.resource_url} for l in d.query(Lesson).filter_by(course_id=cid).all() if l.published or u.role in ("teacher","admin")]
@app.get("/admin/payments")
def payments(d:Session=Depends(dbdep),a:User=Depends(roles("admin"))):
 return [{"learner":d.get(User,p.user_id).full_name,"amount":p.amount,"phone":p.phone,"status":p.status,"receipt":p.receipt} for p in d.query(Payment).all()]
