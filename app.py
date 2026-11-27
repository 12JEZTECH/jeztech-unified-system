import os, hashlib, secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from jose import jwt, JWTError
from sqlalchemy import update, create_engine, String, Integer, Text, DateTime, ForeignKey
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
class PasswordReset(Base):
    __tablename__="password_resets"
    digest:Mapped[str]=mapped_column(String(64),primary_key=True)
    user_id:Mapped[int]=mapped_column(ForeignKey("users.id"),index=True)
    expires:Mapped[datetime]=mapped_column(DateTime)
    used:Mapped[int]=mapped_column(Integer,default=0)
class TuitionAccess(Base):
    __tablename__="tuition_access"
    user_id:Mapped[int]=mapped_column(ForeignKey("users.id"),primary_key=True)
    expires:Mapped[datetime]=mapped_column(DateTime)
class TuitionPayment(Base):
    __tablename__="tuition_payments"
    checkout:Mapped[str]=mapped_column(String(160),primary_key=True)
    user_id:Mapped[int]=mapped_column(ForeignKey("users.id"),index=True)
    amount:Mapped[int]=mapped_column(Integer,default=400)
    verified:Mapped[int]=mapped_column(Integer,default=0)
    created_at:Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
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
@app.post("/api/auth/recovery")
def recovery(data:dict,s:Session=Depends(db)):
    import smtplib
    from email.message import EmailMessage
    email=str(data.get("email","")).strip().lower()
    host=os.getenv("SMTP_HOST")
    sender=os.getenv("SMTP_FROM")
    origin=os.getenv("PUBLIC_BASE_URL","https://jeztech-learning.onrender.com")
    if not host or not sender or not origin.startswith("https://"):
        raise HTTPException(503,"Recovery email service is not configured")
    u=s.query(User).filter_by(email=email).first()
    result={"message":"If the account exists, a recovery link will be sent."}
    if not u: return result
    now=datetime.utcnow()
    if s.query(PasswordReset).filter(PasswordReset.user_id==u.id,PasswordReset.expires>now+timedelta(minutes=14)).first(): return result
    raw=secrets.token_urlsafe(32)
    s.add(PasswordReset(digest=hashlib.sha256(raw.encode()).hexdigest(),user_id=u.id,expires=now+timedelta(minutes=15)))
    s.commit()
    msg=EmailMessage()
    msg["From"]=sender
    msg["To"]=u.email
    msg["Subject"]="JEZTECH Learning password reset"
    msg.set_content("Reset your password within 15 minutes: "+origin.rstrip("/")+"/static/recovery.html#"+raw+"\nIf you did not request this, ignore this email.")
    try:
        with smtplib.SMTP_SSL(host,int(os.getenv("SMTP_PORT","465")),timeout=10) as smtp:
            if os.getenv("SMTP_USER"): smtp.login(os.environ["SMTP_USER"],os.environ["SMTP_PASSWORD"])
            smtp.send_message(msg)
    except Exception:
        import logging
        logging.getLogger(__name__).warning("Recovery email delivery failed")
    return result
@app.post("/api/auth/reset")
def reset_password(data:dict,s:Session=Depends(db)):
    raw=str(data.get("token",""))
    password=str(data.get("password",""))
    if not 12<=len(password)<=128: raise HTTPException(400,"Use 12 to 128 characters")
    digest=hashlib.sha256(raw.encode()).hexdigest()
    row=s.get(PasswordReset,digest)
    if not row: raise HTTPException(400,"Invalid or expired link")
    result=s.execute(update(PasswordReset).where(PasswordReset.digest==digest,PasswordReset.used==0,PasswordReset.expires>datetime.utcnow()).values(used=1))
    if result.rowcount!=1: raise HTTPException(400,"Invalid or expired link")
    u=s.get(User,row.user_id)
    if not u: raise HTTPException(400,"Invalid or expired link")
    u.password_hash=ph(password)
    s.execute(update(PasswordReset).where(PasswordReset.user_id==u.id).values(used=1))
    s.commit()
    return {"message":"Password changed. Sign in with your new password."}
def daraja(path, payload=None):
    import urllib.request, json, base64
    if os.getenv("MPESA_LIVE_ENABLED")!="true":
        raise HTTPException(503,"Live payment verification is not enabled")
    base="https://api.safaricom.co.ke"
    try:
        auth=base64.b64encode((os.environ["MPESA_CONSUMER_KEY"]+":"+os.environ["MPESA_CONSUMER_SECRET"]).encode()).decode()
        req=urllib.request.Request(base+"/oauth/v1/generate?grant_type=client_credentials",headers={"Authorization":"Basic "+auth})
        with urllib.request.urlopen(req,timeout=15) as response: access=json.load(response)["access_token"]
        req=urllib.request.Request(base+path,data=json.dumps(payload).encode(),headers={"Authorization":"Bearer "+access,"Content-Type":"application/json"})
        with urllib.request.urlopen(req,timeout=20) as response: return json.load(response)
    except Exception:
        raise HTTPException(502,"Payment provider unavailable")
def stk_credentials():
    import base64
    from zoneinfo import ZoneInfo
    stamp=datetime.now(ZoneInfo("Africa/Nairobi")).strftime("%Y%m%d%H%M%S")
    key=os.getenv("MPESA_PASSKEY")
    if not key: raise HTTPException(503,"Payment credentials unavailable")
    return {"BusinessShortCode":"522533","Password":base64.b64encode(("522533"+key+stamp).encode()).decode(),"Timestamp":stamp}
@app.get("/api/tuition/status")
def tuition_status(u:User=Depends(allow("student")),s:Session=Depends(db)):
    a=s.get(TuitionAccess,u.id)
    return {"reference":"JZ"+str(u.id),"amount":400,"paybill":"522533","active":bool(a and a.expires>datetime.utcnow()),"expires":a.expires.isoformat()+"Z" if a else None}
@app.post("/api/tuition/trial")
def tuition_trial(u:User=Depends(allow("student")),s:Session=Depends(db)):
    from sqlalchemy.exc import IntegrityError
    if s.get(TuitionAccess,u.id): raise HTTPException(409,"Trial already claimed or subscription exists")
    s.add(TuitionAccess(user_id=u.id,expires=datetime.utcnow()+timedelta(hours=24)))
    try: s.commit()
    except IntegrityError: raise HTTPException(409,"Trial already claimed")
    return {"active":True}
@app.post("/api/tuition/pay")
def tuition_pay(data:dict,u:User=Depends(allow("student")),s:Session=Depends(db)):
    import re
    phone=str(data.get("phone","")).strip()
    if not re.fullmatch(r"254[17][0-9]{8}",phone): raise HTTPException(400,"Use a Kenyan phone number starting 254")
    callback=os.getenv("MPESA_CALLBACK_URL","")
    if callback!="https://jeztech-learning.onrender.com/api/tuition/callback": raise HTTPException(503,"Callback configuration required")
    if s.query(TuitionPayment).filter(TuitionPayment.user_id==u.id,TuitionPayment.created_at>datetime.utcnow()-timedelta(minutes=2)).first(): raise HTTPException(429,"Wait before requesting another payment")
    result=daraja("/mpesa/stkpush/v1/processrequest",{**stk_credentials(),"TransactionType":"CustomerPayBillOnline","Amount":400,"PartyA":phone,"PartyB":"522533","PhoneNumber":phone,"CallBackURL":callback,"AccountReference":"JZ"+str(u.id),"TransactionDesc":"Weekly tuition"})
    if str(result.get("ResponseCode"))!="0" or not result.get("CheckoutRequestID"): raise HTTPException(502,"Payment request rejected")
    p=TuitionPayment(checkout=result["CheckoutRequestID"],user_id=u.id,amount=400)
    s.add(p);s.commit()
    return {"checkout":p.checkout}
@app.post("/api/tuition/callback")
def tuition_callback(data:dict):
    # Callback is untrusted; never grant access based on its contents.
    return {"ResultCode":0,"ResultDesc":"Accepted"}
@app.post("/api/tuition/verify")
def tuition_verify(data:dict,u:User=Depends(allow("student")),s:Session=Depends(db)):
    checkout=str(data.get("checkout",""))
    p=s.get(TuitionPayment,checkout)
    if not p or p.user_id!=u.id: raise HTTPException(404,"Payment not found")
    if p.verified: return {"verified":True}
    result=daraja("/mpesa/stkpushquery/v1/query",{**stk_credentials(),"CheckoutRequestID":checkout})
    if str(result.get("ResultCode"))!="0" or result.get("CheckoutRequestID")!=checkout: return {"verified":False}
    changed=s.execute(update(TuitionPayment).where(TuitionPayment.checkout==checkout,TuitionPayment.verified==0).values(verified=1))
    if changed.rowcount==1:
        a=s.query(TuitionAccess).filter_by(user_id=u.id).with_for_update().first()
        now=datetime.utcnow()
        if a: a.expires=max(now,a.expires)+timedelta(days=7)
        else: s.add(TuitionAccess(user_id=u.id,expires=now+timedelta(days=7)))
        s.commit()
    return {"verified":True}
app.mount("/static",StaticFiles(directory="static"),name="static")
