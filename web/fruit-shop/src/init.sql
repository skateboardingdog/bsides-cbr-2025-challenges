CREATE USER shop WITH PASSWORD 'shop';

CREATE TABLE IF NOT EXISTS flag (
    flag VARCHAR(255) NOT NULL
);

INSERT INTO flag (flag) VALUES ('skbdg{trickysql_woww0w0w0wowowooww0w0w}');

CREATE TABLE IF NOT EXISTS fruit (
    fruit_id SERIAL PRIMARY KEY,
    fruit_name VARCHAR(255) NOT NULL,
    fruit_sku VARCHAR(255) NOT NULL,
    fruit_price INTEGER NOT NULL,
    fruit_user_rating INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vegetable (
    vegetable_id SERIAL PRIMARY KEY,
    vegetable_name VARCHAR(255) NOT NULL,
    vegetable_sku VARCHAR(255) NOT NULL,
    vegetable_price INTEGER NOT NULL,
    vegetable_user_rating INTEGER NOT NULL
);

INSERT INTO fruit (fruit_name, fruit_sku, fruit_price, fruit_user_rating) VALUES
    ('Red Apple', 'FRT-APL-001', 299, 5),
    ('Green Apple', 'FRT-APL-002', 279, 4),
    ('Banana', 'FRT-BAN-001', 199, 5),
    ('Orange', 'FRT-ORG-001', 349, 4),
    ('Strawberry', 'FRT-STR-001', 599, 5),
    ('Mango', 'FRT-MNG-001', 499, 4),
    ('Pineapple', 'FRT-PIN-001', 799, 3),
    ('Watermelon', 'FRT-WTM-001', 899, 5),
    ('Grapes', 'FRT-GRP-001', 699, 4),
    ('Peach', 'FRT-PCH-001', 399, 3),
    ('Pear', 'FRT-PER-001', 329, 3),
    ('Cherry', 'FRT-CHR-001', 899, 5),
    ('Plum', 'FRT-PLM-001', 449, 2),
    ('Kiwi', 'FRT-KIW-001', 349, 4),
    ('Blueberry', 'FRT-BLU-001', 799, 5);

INSERT INTO vegetable (vegetable_name, vegetable_sku, vegetable_price, vegetable_user_rating) VALUES
    ('Carrot', 'VEG-CRT-001', 199, 4),
    ('Broccoli', 'VEG-BRC-001', 349, 5),
    ('Spinach', 'VEG-SPN-001', 299, 4),
    ('Tomato', 'VEG-TOM-001', 249, 5),
    ('Cucumber', 'VEG-CUC-001', 179, 3),
    ('Capsicum', 'VEG-BLP-001', 399, 4),
    ('Lettuce', 'VEG-LET-001', 249, 3),
    ('Onion', 'VEG-ONI-001', 149, 4),
    ('Potato', 'VEG-POT-001', 199, 5),
    ('Sweet Potato', 'VEG-SPT-001', 299, 5),
    ('Corn', 'VEG-CRN-001', 229, 4),
    ('Celery', 'VEG-CEL-001', 199, 2),
    ('Mushroom', 'VEG-MSH-001', 449, 5),
    ('Zucchini', 'VEG-ZUC-001', 279, 3),
    ('Asparagus', 'VEG-ASP-001', 599, 4);

GRANT CONNECT ON DATABASE shopdb TO shop;
GRANT USAGE ON SCHEMA public TO shop;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO shop;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO shop;