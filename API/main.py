# --- main.py ---
# Instala las dependencias necesarias:
# pip install "fastapi[all]" "sqlmodel" "python-jose[cryptography]" "passlib[bcrypt]"

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Field, Session, SQLModel, create_engine, select

from typing import Optional, List
from datetime import datetime, timedelta

# --- 1. Configuración de Seguridad (JWT y Hashing) ---

# Clave secreta para firmar los tokens. ¡Cámbiala por una segura en producción!
SECRET_KEY = "TU_CLAVE_SECRETA_MUY_SEGURA"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Contexto para hashear y verificar contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Esquema de OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- 2. Modelos de Base de Datos (SQLModel) ---

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str

class Transaction(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    description: str
    amount: float
    # "income" o "expense"
    type: str = Field(index=True)
    date: datetime = Field(default_factory=datetime.utcnow, index=True)
    
    owner_id: int = Field(foreign_key="user.id")

# --- 3. Modelos Pydantic (para la API) ---
# Usamos clases separadas para la creación (sin ID) y lectura (con ID)

class TransactionCreate(SQLModel):
    description: str
    amount: float
    type: str
    date: datetime

class Token(SQLModel):
    access_token: str
    token_type: str

class TokenData(SQLModel):
    username: Optional[str] = None

class UserInDB(User):
    pass # Ya tiene todo lo necesario

# --- 4. Configuración de Base de Datos (SQLite) ---

DATABASE_URL = "sqlite:///./tesoreria.db"
engine = create_engine(DATABASE_URL, echo=True)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

# Dependencia para obtener la sesión de la BD
def get_session():
    with Session(engine) as session:
        yield session

# --- 5. Lógica de Autenticación (Helpers) ---

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependencia para obtener el usuario actual desde el token
async def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = session.exec(select(User).where(User.username == token_data.username)).first()
    if user is None:
        raise credentials_exception
    return user

# --- 6. Inicialización de la App FastAPI ---

app = FastAPI()

# Evento de startup para crear la BD y las tablas
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# --- 7. Endpoints de Autenticación y Usuarios ---

# Endpoint para crear un usuario (para probar)
@app.post("/users/", response_model=User)
def create_user(user: User, session: Session = Depends(get_session)):
    hashed_password = get_password_hash(user.hashed_password)
    db_user = User(username=user.username, hashed_password=hashed_password)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

# Endpoint de LOGIN (el que usará tu formulario)
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Endpoint para verificar quién soy (útil para el frontend)
@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# --- 8. Endpoints de Transacciones (Finanzas) ---

# Endpoint para AGREGAR MOVIMIENTO (el que usará tu modal)
@app.post("/transactions/", response_model=Transaction)
def create_transaction(
    transaction: TransactionCreate, 
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    db_transaction = Transaction.from_orm(transaction)
    db_transaction.owner_id = current_user.id
    
    session.add(db_transaction)
    session.commit()
    session.refresh(db_transaction)
    return db_transaction

# Endpoint para OBTENER MOVIMIENTOS RECIENTES (para tu lista)
@app.get("/transactions/", response_model=List[Transaction])
def read_transactions(
    skip: int = 0, 
    limit: int = 100, 
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    transactions = session.exec(
        select(Transaction)
        .where(Transaction.owner_id == current_user.id)
        .order_by(Transaction.date.desc()) # Más recientes primero
        .offset(skip)
        .limit(limit)
    ).all()
    return transactions

# Endpoint para los BALANCES (para tus tarjetas de resumen)
@app.get("/dashboard/stats")
def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    # Lógica para calcular balance total, ingresos del mes, gastos del mes
    # (Esta es una implementación simple, se puede optimizar con SQL puro)
    transactions = session.exec(
        select(Transaction).where(Transaction.owner_id == current_user.id)
    ).all()

    total_balance = 0
    monthly_income = 0
    monthly_expenses = 0
    
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year

    for tx in transactions:
        amount = tx.amount
        if tx.type == "expense":
            amount = -amount
        
        total_balance += amount

        if tx.date.month == current_month and tx.date.year == current_year:
            if tx.type == "income":
                monthly_income += tx.amount
            else:
                monthly_expenses += tx.amount

    return {
        "totalBalance": total_balance,
        "monthlyIncome": monthly_income,
        "monthlyExpenses": monthly_expenses
    }