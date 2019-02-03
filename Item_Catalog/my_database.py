import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Gadget(Base):
    __tablename__ = 'gadget'
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name
            }


class Items(Base):
    __tablename__ = 'items'
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(String())
    price = Column(Integer, nullable=False)
    gadget_id = Column(Integer, ForeignKey('gadget.id'))
    gadget = relationship(Gadget)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return{
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price
            }

engine = create_engine('sqlite:///GadgetDB.db')
Base.metadata.create_all(engine)
