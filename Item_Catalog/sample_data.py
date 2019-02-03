from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from my_database import Base, Gadget, Items, User

engine = create_engine('sqlite:///GadgetDB.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

User1 = User(name="admin", email="deepak.k.ds780@gmail.com")
session.add(User1)
session.commit()

gadget1 = Gadget(name="Laptops", user_id=1)

session.add(gadget1)
session.commit()

item1 = Items(
              name="Dell Inspiron 15 3565", description="Laptop (7th Gen \
              E2-9000/4GB/1TB/Windows 10 /Integrated Graphics), Black,\
              with Preloaded MS- Office", price="$550",
              gadget=gadget1, user_id=1)
session.add(item1)
session.commit()

item2 = Items(
              name="HP 15 Intel Core i5", description="15.6-inch Full HD\
              Laptop(8GB DDR4/1TB HDD/Win 10/MS Office/Integrated\
              Graphics/Sparkling Black/2.04 kg), 15q-ds0029TU",
              price="$700", gadget=gadget1, user_id=1)
session.add(item2)
session.commit()

gadget2 = Gadget(name="Mobiles", user_id=1)

session.add(gadget2)
session.commit()

item1 = Items(
              name="Micromax Canvas Juice 2 AQ5001", description="8MP\
              primary camera, flash and 2MP front facing camera, 5-inch\
              IPS HD capacitive touchscreen with 1280 x 720 pixels resolution,\
              Android v5 Lollipop operating system,\
              2GB RAM, 8GB internal memory, 3000mAH lithium-ion battery",
              price="$90", gadget=gadget2, user_id=1)
session.add(item1)
session.commit()

item2 = Items(
              name="Nokia 6.1", description="16MP rear camera | 8MP front\
              camera, 5.5-inch display, 2.5D corning gorilla glass, Storage\
              and SIM: 4GB RAM | 64GB internal memory, Android v8.0 Oreo\
              operating system,3000mAH lithium-ion battery",
              price="$165", gadget=gadget2, user_id=1)

session.add(item2)
session.commit()

gadget3 = Gadget(name="Smart TV", user_id=1)

session.add(gadget3)
session.commit()

item1 = Items(
              name="Kodak 32HDXSMART (Black)", description="Resolution: HD Ready\
              (1366x768p), Display: HD Ready | A+ Grade IPS Panel | Premium\
              Finish Design, Connectivity: 3 HDMI ports to connect set top\
              box,Sound: 20 Watts Output | In-built box speakers",
              price="$198", gadget=gadget3, user_id=1)
session.add(item1)
session.commit()

item2 = Items(
              name="Kevin K32CV338H (Black)", description="Resolution: HD\
              Ready 1366x768p) Viewing Angle: 178 degrees, Display: HRDD\
              Techonology | Cinema Mode |Supports 16.7 million colours",
              price="$180", gadget=gadget3, user_id=1)
session.add(item2)
session.commit()

print "Success"
