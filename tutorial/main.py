from fastapi import (
    FastAPI, Form, File, UploadFile, HTTPException, Depends,
    Cookie, Header
)
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import (
    http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import (
    JSONResponse, HTMLResponse, PlainTextResponse
)
from starlette.status import HTTP_401_UNAUTHORIZED
import time
from typing import List, Optional, Set


app = FastAPI()

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

fake_db = {}

class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: str = None


class UserIn(UserBase):
    password: str


class UserOut(UserBase):
    pass


class UserInDB(UserBase):
    hashed_password: str

class UnicornException(Exception):
    def __init__(self, name: str):
        self.name = name

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request, exc):
    print(f"OMG! An HTTP error!: {exc}")
    return await http_exception_handler(request, exc)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    print(f"OMG! The client sent invalid data!: {exc}")
    return await request_validation_exception_handler(request, exc)

@app.get("/items/{item_id}", tags=["Items"])
async def read_item(item_id: int):
    if item_id == 3:
        raise HTTPException(status_code=418, detail="Nope! I don't like 3.")
    return {"item_id": item_id}

class Item(BaseModel):
    name: str
    description: str = None
    price: float
    tax: float = None
    tags: Set[str] = []


@app.post(
    "/items/", 
    response_model=Item, 
    response_description="The created item",
    summary="Create an item", 
    tags=["Items"],
    
)
async def create_item(*, item: Item):
    """
    Create an item with all the information:

    - **name**: each item must have a name
    - **description**: a long description
    - **price**: required
    - **tax**: if the item doesn't have tax, you can omit this
    - **tags**: a set of unique tag strings for this item
    """
    return item

@app.put(
        "/items/{id}",
        response_model=Item, 
        response_description="The modified item",
        summary="Modify an item", 
        tags=["Items"],
    )
def update_item(id: str, item: Item):
    """
    Modify an item with all the information:

    - **name**: each item must have a name
    - **description**: a long description
    - **price**: required
    - **tax**: if the item doesn't have tax, you can omit this
    - **tags**: a set of unique tag strings for this item
    """
    json_compatible_item_data = jsonable_encoder(item)
    fake_db[id] = json_compatible_item_data
    return json_compatible_item_data

@app.patch(
    "/items/{item_id}", 
    response_model=Item,
    response_description="The modified item",
    summary="Modify an item", 
    tags=["Items"],
)
async def partial_update_item(item_id: str, item: Item):
    """
    Modify an item with partial information:

    - **name**: each item must have a name
    - **description**: a long description
    - **price**: required
    - **tax**: if the item doesn't have tax, you can omit this
    - **tags**: a set of unique tag strings for this item
    """
    stored_item_data = fake_db[item_id]
    stored_item_model = Item(**stored_item_data)
    update_data = item.dict(exclude_unset=True)
    updated_item = stored_item_model.copy(update=update_data)
    fake_db[item_id] = jsonable_encoder(updated_item)
    return updated_item

@app.exception_handler(UnicornException)
async def unicorn_exception_handler(request: Request, exc: UnicornException):
    return JSONResponse(
        status_code=418,
        content={"message": f"Oops! {exc.name} did something. There goes a rainbow..."},
    )

def fake_password_hasher(raw_password: str):
    return "supersecret" + raw_password


def fake_save_user(user_in: UserIn):
    hashed_password = fake_password_hasher(user_in.password)
    user_in_db = UserInDB(**user_in.dict(), hashed_password=hashed_password)
    print("User saved! ..not really")
    print(user_in_db)
    print(UserOut(**user_in_db.dict()))
    return user_in_db


@app.post("/user/", response_model=UserOut, tags=["User"])
async def create_user(*, user_in: UserIn):
    user_saved = fake_save_user(user_in)
    return user_saved


@app.post("/login/", tags=["User"])
async def login(*, username: str = Form(...), password: str = Form(...)):
    return {"username": username}

@app.post("/file/" , tags=["Upload"])
async def create_file(file: bytes = File(...)):
    return {"file_size": len(file)}


@app.post("/uploadfile/", tags=["Upload"])
async def create_upload_file(file: UploadFile = File(...)):
    return {"filename": file.filename}

@app.post("/files/", tags=["Upload"])
async def create_files(files: List[bytes] = File(...)):
    return {"file_sizes": [len(file) for file in files]}

@app.post("/uploadfiles/", tags=["Upload"])
async def create_upload_files(files: List[UploadFile] = File(...)):
    return {"filenames": [file.filename for file in files]}

@app.get("/", tags=["Index"])
async def main():
    content = """
<body>
<form action="/files/" enctype="multipart/form-data" method="post">
<input name="files" type="file" multiple>
<input type="submit">
</form>
<form action="/uploadfiles/" enctype="multipart/form-data" method="post">
<input name="files" type="file" multiple>
<input type="submit">
</form>
</body>
    """
    return HTMLResponse(content=content)

@app.get("/unicorns/{name}", tags=["Unicorn"], deprecated=True,)
async def read_unicorn(name: str):
    if name == "yolo":
        raise UnicornException(name=name)
    return {"unicorn_name": name}


#### Depends as a function

async def common_parameters(q: str = None, skip: int = 0, limit: int = 100):
    return {"q": q, "skip": skip, "limit": limit}

@app.get("/foo/", tags=["Depends"])
async def read_foo(commons: dict = Depends(common_parameters)):
    return commons


@app.get("/bar/", tags=["Depends"])
async def read_bar(commons: dict = Depends(common_parameters)):
    return commons


### Depends as a class

fake_items_db = [{"item_name": "Foo"}, {"item_name": "Bar"}, {"item_name": "Baz"}]


class CommonQueryParams:
    def __init__(self, q: str = None, skip: int = 0, limit: int = 100):
        self.q = q
        self.skip = skip
        self.limit = limit


@app.get("/ditems/", tags=["Depends"])
async def read_ditems(commons: CommonQueryParams = Depends()):
    response = {}
    if commons.q:
        response.update({"q": commons.q})
    items = fake_items_db[commons.skip : commons.skip + commons.limit]
    response.update({"items": items})
    return response

### Sub dependencies

def query_extractor(q: str = None):
    return q

def query_or_cookie_extractor(
    q: str = Depends(query_extractor), last_query: str = Cookie(None)
):
    if not q:
        return last_query
    return q

@app.get("/query-or-default/", tags=["Depends"])
async def read_query(query_or_default: str = Depends(query_or_cookie_extractor)):
    return {"q_or_cookie": query_or_default}


### Verify Key / Token

async def verify_token(x_token: str = Header(...)):
    if x_token != "fake-super-secret-token":
        raise HTTPException(status_code=400, detail="X-Token header invalid")


async def verify_key(x_key: str = Header(...)):
    if x_key != "fake-super-secret-key":
        raise HTTPException(status_code=400, detail="X-Key header invalid")
    return x_key


@app.get("/verify/", dependencies=[Depends(verify_token), Depends(verify_key)])
async def read_items():
    return [{"item": "Foo"}, {"item": "Bar"}]


# OAuth Base

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


@app.get("/items-auth/")
async def read_items_auth(token: str = Depends(oauth2_scheme)):
    return {"token": token}


# Extending OAth depends with a get user middleware

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


def fake_decode_token(token):
    return User(
        username=token + "fakedecoded", email="john@example.com", full_name="John Doe"
    )


async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    return user


@app.get("/users/me", tags=["User"])
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


# Add in fake auth verification....

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

def fake_hash_password(password: str):
    return "fakehashed" + password

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def fake_decode_token_two(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user

async def get_current_user_two(token: str = Depends(oauth2_scheme)):
    print('there')
    user = fake_decode_token_two(token)
    if not user:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user_two)):
    print('here')
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login_two(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me-two", tags=["User"])
async def read_users_me_two(current_user: User = Depends(get_current_active_user)):
    return current_user