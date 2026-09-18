from backend.database import engine, Base
from backend.models import User, Message

print("Создаем таблицы в PostgreSQL...")
Base.metadata.create_all(bind=engine)
print("✨ Успех! Таблицы 'users' и 'messages' успешно созданы!")
