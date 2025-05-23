import stripe
import bcchapi
stripe.api_key = "sk_test_51RRm9aPT2b6bwjtChm60ypBQMIBxYK7lruxTKDFQ2eIvoP6fEoSBEbEYNf6BmDoD6tAOz9NPaWWiEWnhLivXIxjF000MYxOqYr"
from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from uuid import uuid4

# === CONFIGURACIÓN ===
SECRET_KEY = "clave_ultra_segura"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# === BASE DE DATOS SIMULADA ===
usuarios_db = {}
productos_db = {}
sucursales_db = {}
vendedores_db = {}
pedidos_db = []

roles_permitidos = ["Administrador", "Mantenedor", "Jefe de tienda", "Bodega", "Cliente", "Cuentas de servicio"]

# === MODELOS ===
class UserRegister(BaseModel):
    user: str
    pwd: str
    email: EmailStr
    rol: str = "Cliente"

class UserLogin(BaseModel):
    user: str
    pwd: str

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

class Producto(BaseModel):
    id: str
    nombre: str
    categoria: str
    precio: float
    stock: int
    marca: str
    codigo: str
    enPromocion: bool = False
    esNuevo: bool = False

class Pedido(BaseModel):
    usuario: str
    producto_id: str
    cantidad: int

class Contacto(BaseModel):
    nombre: str
    email: EmailStr
    mensaje: str

# === AUTENTICACIÓN ===
security = HTTPBearer()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        rol = payload.get("rol")
        if username is None or rol.lower() not in [r.lower() for r in roles_permitidos]:
            raise credentials_exception
        return {"user": username, "rol": rol}
    except JWTError:
        raise credentials_exception

# === APP ===
app = FastAPI(title="API FERREMAS", version="1.0.0")

# === USUARIOS PREDEFINIDOS ===
usuarios_iniciales = [
    {"user": "javier_thompson", "password": "aONF4d6aNBIxRjlgjBRRzrS", "role": "Administrador"},
    {"user": "ignacio_tapia", "password": "f7rWChmQS1JYfThT", "role": "Cliente"},
    {"user": "stripe_sa", "password": "dzkQqDL9XZH33YDzhmsf", "role": "Cuentas de servicio"},
]

for usuario in usuarios_iniciales:
    if usuario["user"] not in usuarios_db:
        usuarios_db[usuario["user"]] = {
            "user": usuario["user"],
            "pwd": get_password_hash(usuario["password"]),
            "email": f"{usuario['user']}@ferremas.cl",
            "rol": usuario["role"]
        }

# === PRODUCTOS Y SUCURSALES PREDEFINIDOS ===

productos_iniciales = [
    {
        "id": str(uuid4()),
        "nombre": "Taladro inalámbrico",
        "categoria": "Herramientas eléctricas",
        "precio": 49990,
        "stock": 10,
        "marca": "Bosch",
        "codigo": "BOS-TAL-001",
        "enPromocion": True,
        "esNuevo": False
    },
    {
        "id": str(uuid4()),
        "nombre": "Caja de herramientas 50 piezas",
        "categoria": "Accesorios",
        "precio": 29990,
        "stock": 15,
        "marca": "Stanley",
        "codigo": "STA-CAJ-050",
        "enPromocion": False,
        "esNuevo": True
    },
    {
        "id": str(uuid4()),
        "nombre": "Juego de destornilladores",
        "categoria": "Manuales",
        "precio": 9990,
        "stock": 50,
        "marca": "Truper",
        "codigo": "TRU-DES-007",
        "enPromocion": False,
        "esNuevo": False
    }
]

for producto in productos_iniciales:
    productos_db[producto["id"]] = producto

sucursales_iniciales = [
    {
        "id": "scl001",
        "nombre": "Sucursal Santiago Centro",
        "direccion": "Av. Libertador Bernardo O'Higgins 1234, Santiago",
        "telefono": "+56 2 1234 5678"
    },
    {
        "id": "vln002",
        "nombre": "Sucursal Viña del Mar",
        "direccion": "Av. Libertad 4321, Viña del Mar",
        "telefono": "+56 32 1234 567"
    }
]

for sucursal in sucursales_iniciales:
    sucursales_db[sucursal["id"]] = sucursal

# === ENDPOINTS ===
@app.get("/")
def home():
    return {"mensaje": "API FERREMAS operativa"}

@app.post("/registro")
def register(payload: UserRegister):
    if payload.user in usuarios_db:
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    usuarios_db[payload.user] = {
        "user": payload.user,
        "pwd": get_password_hash(payload.pwd),
        "email": payload.email,
        "rol": payload.rol
    }
    return {"mensaje": "Usuario registrado correctamente"}

@app.post("/login", response_model=Token)
def login(payload: UserLogin):
    user = usuarios_db.get(payload.user)
    if not user or not verify_password(payload.pwd, user["pwd"]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    token = create_access_token({"sub": payload.user, "rol": user["rol"]})
    return {"access_token": token, "token_type": "bearer", "role": user["rol"]}

@app.get("/productos", response_model=List[Producto])
def obtener_productos():
    return list(productos_db.values())

@app.get("/productos/promocion", response_model=List[Producto])
def obtener_productos_promocion():
    return [p for p in productos_db.values() if p["enPromocion"]]

@app.get("/productos/novedades", response_model=List[Producto])
def obtener_productos_nuevos():
    return [p for p in productos_db.values() if p["esNuevo"]]

@app.get("/productos/{producto_id}", response_model=Producto)
def obtener_producto(producto_id: str):
    producto = productos_db.get(producto_id)
    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado")
    return producto

@app.post("/productos")
def agregar_producto(producto: Producto, user=Depends(get_current_user)):
    if user["rol"].lower() not in ["administrador", "mantenedor"]:
        raise HTTPException(status_code=403, detail="Permisos insuficientes")
    productos_db[producto.id] = producto.dict()
    return {"mensaje": "Producto agregado exitosamente"}

@app.get("/sucursales")
def obtener_sucursales():
    return list(sucursales_db.values())

@app.get("/sucursales/{sucursal_id}")
def obtener_sucursal(sucursal_id: str):
    return sucursales_db.get(sucursal_id, {"detalle": "Sucursal no encontrada"})

@app.get("/vendedores/{sucursal_id}")
def obtener_vendedores(sucursal_id: str):
    return [v for v in vendedores_db.values() if v["sucursal_id"] == sucursal_id]

@app.post("/pedido")
def colocar_pedido(pedido: Pedido, user=Depends(get_current_user)):
    if user["rol"].lower() != "cliente":
        raise HTTPException(status_code=403, detail="Sólo clientes pueden hacer pedidos")
    producto = productos_db.get(pedido.producto_id)
    if not producto or pedido.cantidad > producto["stock"]:
        raise HTTPException(status_code=400, detail="Producto no disponible o stock insuficiente")
    producto["stock"] -= pedido.cantidad
    pedidos_db.append({
        "usuario": user["user"],
        "producto": producto["nombre"],
        "cantidad": pedido.cantidad,
        "timestamp": datetime.utcnow().isoformat()
    })
    return {"mensaje": "Pedido realizado correctamente"}

@app.post("/contacto")
def solicitar_contacto(datos: Contacto):
    return {
        "mensaje": "Solicitud recibida. Un vendedor se pondrá en contacto.",
        "nombre": datos.nombre,
        "email": datos.email
    }

@app.get("/tipo-cambio/hoy")
def obtener_tipo_cambio_hoy(user=Depends(get_current_user)):
    # Validar roles permitidos para consultar tipo de cambio
    if user["rol"].lower() not in ["administrador", "mantenedor"]:
        raise HTTPException(status_code=403, detail="Permisos insuficientes")

    hoy = datetime.today().strftime("%Y-%m-%d")

    try:
        # Crear instancia bcchapi con credenciales directamente
        siete = bcchapi.Siete("matiasheat25@gmail.com", "12345Alejandro")

        # Solicitar el tipo de cambio para la fecha de hoy
        df = siete.cuadro(
            series=["F073.TCO.PRE.Z.D"],  # Código tipo de cambio
            nombres=["tipo_cambio"],
            desde=hoy,
            hasta=hoy
        )

        # Validar si la respuesta tiene datos
        if df.empty:
            raise HTTPException(status_code=404, detail="No hay datos para hoy")

        valor = df["tipo_cambio"].iloc[0]

        return {
            "fecha": hoy,
            "tipo_cambio": float(valor)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener el tipo de cambio: {str(e)}")

# === STRIPE - CREAR PAGO ===
@app.post("/crear_pago")
def crear_pago(monto: int = Body(..., embed=True)):
    try:
        intent = stripe.PaymentIntent.create(
            amount=monto,  # Monto en centavos, ej: 1000 = $10.00
            currency="clp",
            payment_method_types=["card"],
        )
        return {"client_secret": intent.client_secret}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# === PERSONALIZACIÓN SWAGGER CON TOKEN ===
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description="Documentación de la API FERREMAS con autenticación Bearer",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method.setdefault("security", []).append({"BearerAuth": []})
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi