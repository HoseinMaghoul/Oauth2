from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import uvicorn


SECRET_KEY = "9edb3db96891081947dcfc1083b840813e8cf4a696a57b7acac17c4c9c49c2be"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30







db = {
    "hosein":{
        "usernames": "hosein",
        "full_name": "maghoul",
        "email": "maghoul@gmail.com",
        "hashed_password": "$2b$12$DFaQavtipxLcoFMEVJfVKuhTrBCIgb/MvIE.EcxI/PtznD/EIh9IS",
        "disabled": False
    }
}


 
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str or None = None



class User(BaseModel):
    username: str
    email: str or None = None
    full_name: str or None = None
    dishabled: bool or None = None


class UserInDB(User):
    hashed_password: str





pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")
oauth2_schema = OAuth2PasswordBearer(tokenUrl="token")


app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)



def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        user_data["username"] = username
        return UserInDB(**user_data)
    


#________________________________________________________________________________________________________________________________


def authenticate_user(db, username: str, password:str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    
    return user


#__________________________________________________________________


def create_access_token(data: dict, expire_delta:timedelta or None = None):
    to_encode = data.copy()
    if expire_delta: 
        expire = datetime.utcnow() + expire_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encode_jwt


 


async def get_currnet_user(token: str = Depends(oauth2_schema)):
    creaditional_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                           detail="could not validate", headers={"WWW-Authenticate":"Bearer"})
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise creaditional_exception
      
        token_data = TokenData(username=username)
    except JWTError:
        raise creaditional_exception
    
    user = get_user(db, username=token_data.username)
    if user is None:
        raise creaditional_exception
    return user


def get_current_active_user(current_user:UserInDB = Depends(get_currnet_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    
    print("Authenticated")
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                            detail="Incorrect username or password", headers={"WWW-Authenticate":"Bearer"})
   
    accesss_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub":user.username}, expire_delta=accesss_token_expires)
    return{"access_token":access_token, "token_type": "bearer"}



@app.get('/users/me/', response_model=User)
def read_user_me(current_user: User = Depends(get_current_active_user)):
    return current_user




@app.get('/users/me/itmes/')
def read_own_itmes(current_user: User = Depends(get_current_active_user)):
    return [{"itme_id": 1, "owner": current_user}]




# pwd = get_password_hash("123")
# print(pwd)



if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)





