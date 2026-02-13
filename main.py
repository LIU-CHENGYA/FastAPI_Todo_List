from datetime import datetime, timedelta, timezone
from typing import Annotated
import jwt
import json
import mysql.connector
from fastapi import Depends, FastAPI, HTTPException, status,Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles

# --- 1. 初始化與資料庫 ---
app = FastAPI() 

con = mysql.connector.connect(
    user="fastapi_user",
    password="110305ms",
    host="localhost",
    database="fastapi"
)

# con = mysql.connector.connect(
#     user="root",
#     password="110305103ms",
#     host = "localhost",
#     database="fastapi"
# )

# --- 2. 配置與安全工具 ---
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["argon2","bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 這裡暫時保留 fake_db 供練習，之後可以改從 MySQL 撈
# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "hashed_password": pwd_context.hash("secret123"),
#         "disabled": False,
#     },
#     "vivian": {
#         "username": "vivian",
#         "full_name": "ca",
#         "hashed_password": pwd_context.hash("kkvv89"),
#         "disabled": False,
#     }

# }

# 定義 Todo 的資料結構，讓 FastAPI 自動幫你解析 JSON
class TodoItem(BaseModel):
    content:str
    status:bool = False
    

class profile(BaseModel):
    username:str
    password:str

# --- 3. 核心功能函數 ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="無法驗證憑證",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # 解碼並驗證 JWT
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token 已過期")
    except InvalidTokenError:
        raise credentials_exception
    
    # 資料庫
    cursor = con.cursor(dictionary=True)
    cursor.execute("SELECT * FROM profile WHERE username=%s",[username])
    user = cursor.fetchone()

    #user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception
    return user

# --- 4. API 路徑  ---

#登入api
@app.post("/login")
async def login(log:profile):
    
    # 資料庫
    cursor = con.cursor(dictionary=True)
    cursor.execute("SELECT * FROM profile WHERE username=%s",[log.username])
    user = cursor.fetchone()


    #user = fake_users_db.get(log.username)
    if not user or not verify_password(log.password, user["password"]):
        raise HTTPException(status_code=400, detail="帳號或密碼錯誤")

    
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# #登出api
# 好像不用寫:但為了更安全可以寫

# 註冊api=>存到資料庫中
@app.post("/register")
def registration (acc:profile):
    #連線資料庫
    try:
        #檢查是否有相同的帳號名稱
        cursor = con.cursor(dictionary=True)
        cursor.execute("SELECT * FROM profile WHERE username=%s",[acc.username] )
        result = cursor.fetchone()
        if result == None: #可以成功註冊，寫入資料庫
            cursor.execute("INSERT INTO profile (username,password) VALUES (%s,%s)",[acc.username,pwd_context.hash(acc.password)])
            con.commit()
            return {"ok":True}
        else: #使用名稱重複
            return {"ok":False}
    finally:
        cursor.close()
    
    



#新增待辦事項
@app.post("/api/todo")
def add_todo(item: TodoItem,current_user: Annotated[dict, Depends(get_current_user)]):
    #連線資料庫
    cursor = con.cursor()
    ## 這裡的 owner 來源是 current_user["username"]，不是 item.owner
    cursor.execute("INSERT INTO todo_list (content,status,owner) VALUES(%s,%s,%s)",[item.content,item.status,current_user["username"]])
    con.commit()
    return {"ok":True}


#查看全部待辦
@app.get("/api/todo")
def retrive_todo(current_user: Annotated[dict, Depends(get_current_user)]):

    #連線資料庫
    cursor = con.cursor(dictionary =True)
    cursor.execute("SELECT * FROM todo_list WHERE owner=%s",[current_user["username"]])
    data = cursor.fetchall()
    return data

#更新待辦狀態(完成/未完成)或是文字內容
@app.put("/api/todo/{id}") # 在 REST 設計裡，資源的唯一識別通常放在路徑，而不是 query string
def update_todo(id:int ,item: TodoItem ,current_user: Annotated[dict, Depends(get_current_user)]):
    #連線資料庫
    cursor = con.cursor()
    cursor.execute("UPDATE todo_list SET status=%s, content=%s,owner=%s WHERE id=%s",[item.status,item.content,current_user["username"],id])
    con.commit()
    return {"ok":True}


#刪除待辦
@app.delete("/api/todo/{id}")
def delete_todo(id:int,current_user: Annotated[dict, Depends(get_current_user)]):
    #連線資料庫
    cursor = con.cursor()
    cursor.execute("DELETE FROM todo_list  WHERE id=%s",[id])
    con.commit()
    return {"ok":True}

app.mount("/",StaticFiles(directory="public",html=True))


