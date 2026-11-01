-- Run this ONCE in Supabase Dashboard -> SQL Editor
create table users(id integer generated always as identity primary key, name text not null, email text unique not null, pass text not null,
  role text not null default 'user' check(role in ('user','admin')));
create table sessions(token text primary key, user_id integer not null references users(id) on delete cascade,
  expires_at timestamptz not null default now() + interval '7 days');
create table products(id integer generated always as identity primary key, name text not null, category text not null,
  price integer not null check(price >= 0), stock integer not null check(stock >= 0), emoji text default '🛍️', image text default '', active boolean not null default true);
create table coupons(code text primary key, pct integer not null check(pct between 1 and 90));
create table orders(id integer generated always as identity primary key, user_id integer not null references users(id), name text, phone text, address text,
  slot text, payment text, coupon text, discount integer not null default 0, total integer not null default 0,
  status text not null default 'Placed' check(status in ('Placed','Packed','Shipped','Delivered')), created_at timestamptz not null default now());
create table order_items(order_id integer not null references orders(id) on delete cascade, product_id integer not null references products(id),
  qty integer not null check(qty > 0), price integer not null);
create table wishlist(user_id integer references users(id) on delete cascade, product_id integer references products(id) on delete cascade, primary key(user_id, product_id));
create table reviews(id integer generated always as identity primary key, product_id integer not null references products(id) on delete cascade,
  user_id integer not null references users(id) on delete cascade, name text, stars integer not null check(stars between 1 and 5), text text, unique(product_id, user_id));

create index ix_products_cat on products(category) where active;
create index ix_items_order on order_items(order_id);
create index ix_items_product on order_items(product_id);
create index ix_orders_user on orders(user_id);
create index ix_orders_created on orders(created_at);
create index ix_sessions_exp on sessions(expires_at);

-- Security: block Supabase's public Data API from touching these tables.
-- Our Node server connects directly as the database owner, so it is not affected.
alter table users enable row level security;     alter table sessions enable row level security;
alter table products enable row level security;  alter table coupons enable row level security;
alter table orders enable row level security;    alter table order_items enable row level security;
alter table wishlist enable row level security;  alter table reviews enable row level security;

insert into products(name,category,price,stock,emoji) values
 ('Filter Coffee Powder 500g','Coffee',320,40,'☕'),('Arabica Beans 250g','Coffee',450,25,'🫘'),
 ('Instant Decoction Pack','Coffee',180,60,'🥛'),('Steel Davara Set','Gear',399,30,'🥄'),
 ('Pour-over Dripper','Gear',899,12,'⏳'),('Hand Grinder','Gear',1499,4,'⚙️'),
 ('Murukku Box','Snacks',150,50,'🌀'),('Jaggery Cookies','Snacks',210,35,'🍪');
insert into coupons values('WELCOME10',10),('SAVE20',20);
