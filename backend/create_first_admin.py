import getpass
from app.main import Base, engine, SessionLocal, User, pwd
Base.metadata.create_all(engine)
db=SessionLocal()
try:
 if db.query(User).filter_by(role="admin").first(): raise SystemExit("Admin already exists; refusing bootstrap.")
 name=input("Administrator full name: ").strip()
 email=input("Administrator email: ").strip().lower()
 password=getpass.getpass("Password (12+ characters): ")
 if len(password)<12: raise SystemExit("Use at least 12 characters.")
 db.add(User(email=email,full_name=name,password_hash=pwd.hash(password),role="admin",active=True));db.commit()
 print("First administrator created.")
finally: db.close()
