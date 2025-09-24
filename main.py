from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional
from passlib.context import CryptContext

SECRET_KEY="371e720396f6b7725be68f324145aefa20bc8b0d70bc84590fdec50d664ff94f"
ALGRITHM = 'H256'
ACCESS_TOKEN_EXPIRE_MINUTES=30

db = {
   'karan':{
        'username':"karan",
        "full_name":"Karan Kumar",
        "email":"karanmalhi@gmail.com",
        "hashed_password":"",
        "disable":False
    }
}
class Token(BaseModel):
    access_token:str
    token_type:str

class TokenData(BaseModel):
    username:Optional[str] = None

class User(BaseModel):
    username:str
    email:Optional[str] = None
    full_name:Optional[str] = None
    disabled:Optional[bool] = None


class UserInDB(User):
    hashed_password:str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth_2_scheme= OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username:str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)
    
def authenticate_user(db, username:str, password:str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data:dict,expire_dalta:Optional[timedelta] = None):
    to_encode = data.copy()
    if expire_dalta:
        expire = datetime.utcnow() + expire_dalta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp":expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGRITHM)
    return encoded_jwt


async def get_current_user(token:str = Depends(oauth_2_scheme)):
    crendential_expcetion = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Cloud not validate credenitails", headers={"WWW-Authenticate":"Bearer "})

    try:
        payload = jwt.decode(token, SECRET_KEY,algorithms=[ALGRITHM])
        username:str = payload.get("sub")
        if username is None:
            raise crendential_expcetion
        token_data = TokenData(username = username)
    except JWTError:
        raise crendential_expcetion
    
    user = get_user(db, username=token_data.username)
    return user

async def get_current_active_user(current_user:UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    return current_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data:OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username,form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="incorrect password",headers={"WWW-Authenticate":"Bearer "})
    accuess_token_expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub":user.username}, expire_dalta=accuess_token_expire)
    return {"access_token":access_token, "token_type":"bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user:User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items", response_model=User)
async def read_own_item(current_user:User = Depends(get_current_active_user)):
    return [{"item_id":1, "owner":current_user}]

pwd = get_password_hash("karan123")
print(pwd)