// Filename: app.js (or server.js)

const express = require('express');
const mysql = require('mysql2/promise'); // Using mysql2 for promise-based queries
const bcrypt = require('bcryptjs'); // For password hashing
const jwt = require('jsonwebtoken'); // For user authentication (JWT)
const cors = require('cors'); // For handling Cross-Origin Resource Sharing

const app = express();
const PORT = process.env.PORT || 3000; // Server port

// Middleware
app.use(cors()); // Enable CORS for all origins (for development)
app.use(express.json()); // Parse JSON request bodies

// --- MySQL Database Connection ---
const dbConfig = {
    host: 'localhost', // Your MySQL host
    user: 'Forum-dev',      // Your MySQL username
    password: 'root', // <--- IMPORTANT: Replace with your MySQL password
    database: 'kolo'   // The database name as requested
};

let dbConnectionPool; // Use a connection pool for better performance

async function connectToDatabase() {
    try {
        dbConnectionPool = await mysql.createPool(dbConfig);
        console.log('Connected to MySQL database "kolo" successfully!');
        // Optional: Create tables if they don't exist
        await createTables();
    } catch (err) {
        console.error('Failed to connect to MySQL:', err);
        process.exit(1); // Exit process if database connection fails
    }
}

// --- Database Table Creation (Run once, or use migrations) ---
async function createTables() {
    try {
        // Users table
        await dbConnectionPool.execute(`
            CREATE TABLE IF NOT EXISTS users (
                user_id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('Table "users" checked/created.');

        // Products table
        await dbConnectionPool.execute(`
            CREATE TABLE IF NOT EXISTS products (
                product_id INT AUTO_INCREMENT PRIMARY KEY,
                product_name VARCHAR(255) NOT NULL,
                description TEXT,
                price DECIMAL(10, 2) NOT NULL,
                image_url VARCHAR(255),
                stock_quantity INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('Table "products" checked/created.');

        // Orders table
        await dbConnectionPool.execute(`
            CREATE TABLE IF NOT EXISTS orders (
                order_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                total_amount DECIMAL(10, 2) NOT NULL,
                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                order_status VARCHAR(50) DEFAULT 'Pending',
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            );
        `);
        console.log('Table "orders" checked/created.');

        // Order Items table (details of products within an order)
        await dbConnectionPool.execute(`
            CREATE TABLE IF NOT EXISTS order_items (
                order_item_id INT AUTO_INCREMENT PRIMARY KEY,
                order_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL,
                price_at_purchase DECIMAL(10, 2) NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders(order_id),
                FOREIGN KEY (product_id) REFERENCES products(product_id)
            );
        `);
        console.log('Table "order_items" checked/created.');

        // Optional: Insert some dummy products if the table is empty
        const [rows] = await dbConnectionPool.execute('SELECT COUNT(*) AS count FROM products');
        if (rows[0].count === 0) {
            console.log('Inserting dummy products...');
            await dbConnectionPool.execute(`
                INSERT INTO products (product_name, description, price, image_url, stock_quantity) VALUES
                ('Wireless Headphones', 'Experience crystal-clear audio with these comfortable wireless headphones. Perfect for music lovers and gamers alike.', 99.99, 'https://placehold.co/300x300/F0F9FF/1F2937?text=Headphones', 50),
                ('Smartwatch Pro', 'Stay connected and track your fitness goals with the new Smartwatch Pro. Features heart rate monitoring, GPS, and long battery life.', 199.99, 'https://placehold.co/300x300/F0F9FF/1F2937?text=Smartwatch', 30),
                ('Portable Bluetooth Speaker', 'Take your music anywhere with this compact and powerful Bluetooth speaker. Waterproof and durable for outdoor adventures.', 49.99, 'https://placehold.co/300x300/F0F9FF/1F2937?text=Speaker', 100),
                ('Gaming Mouse', 'Precision gaming mouse with customizable RGB lighting and ergonomic design for long gaming sessions.', 34.99, 'https://placehold.co/300x300/F0F9FF/1F2937?text=Gaming+Mouse', 75),
                ('USB-C Hub', 'Expand your laptops connectivity with this versatile USB-C hub, featuring multiple ports for all your peripherals.', 29.99, 'https://placehold.co/300x300/F0F9FF/1F2937?text=USB-C+Hub', 120),
                ('Ergonomic Keyboard', 'Boost your productivity and comfort with this full-size ergonomic keyboard, designed for natural typing posture.', 79.99, 'https://placehold.co/300x300/F0F9FF/1F2937?text=Keyboard', 60),
                ('Webcam 1080p', 'High-definition 1080p webcam perfect for video calls, streaming, and online meetings.', 59.99, 'https://placehold.co/300x300/F0F9FF/1F2937?text=Webcam', 40),
                ('External SSD 1TB', 'Fast and reliable 1TB external SSD for backing up your important files and expanding storage.', 119.99, 'https://placehold.co/300x300/F0F9FF/1F2937?text=SSD', 25);
            `);
            console.log('Dummy products inserted.');
         }

    } catch (err) {
        console.error('Error creating tables or inserting dummy data:', err);
    }
}


// --- JWT Secret (KEEP THIS SECURE IN PRODUCTION) ---
const JWT_SECRET = 'your_super_secret_jwt_key_please_change_this_in_production'; // Replace with a strong, random secret

// --- Middleware for JWT Authentication ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.status(401).json({ message: 'Authentication token required.' }); // If no token

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.status(403).json({ message: 'Invalid or expired token.' }); // If token is not valid
        }
        req.user = user; // Attach user payload (e.g., { id: userId, username: '...' }) to request
        next();
    });
};

// --- API Routes ---

// 1. User Registration
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }
    if (username.length < 3 || password.length < 6) {
        return res.status(400).json({ message: 'Username must be at least 3 characters and password at least 6 characters long.' });
    }

    try {
        // Check if user already exists
        const [existingUsers] = await dbConnectionPool.execute('SELECT user_id FROM users WHERE username = ?', [username]);
        if (existingUsers.length > 0) {
            return res.status(409).json({ message: 'Username already exists. Please choose a different one.' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10); // Salt rounds: 10

        // Insert new user into database
        const [result] = await dbConnectionPool.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            [username, passwordHash]
        );
        res.status(201).json({ message: 'User registered successfully!', userId: result.insertId });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// 2. User Login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        // Find user by username
        const [users] = await dbConnectionPool.execute('SELECT user_id, username, password_hash FROM users WHERE username = ?', [username]);
        const user = users[0];

        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        // Compare provided password with hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user.user_id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

        res.json({ message: 'Login successful!', token, username: user.username, userId: user.user_id });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// 3. Get All Products
app.get('/api/products', async (req, res) => {
    try {
        const [products] = await dbConnectionPool.execute('SELECT product_id, product_name, description, price, image_url, stock_quantity FROM products');
        res.json(products);
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ message: 'Server error fetching products.' });
    }
});

// 4. Get Product by ID
app.get('/api/products/:id', async (req, res) => {
    const productId = req.params.id;
    try {
        const [products] = await dbConnectionPool.execute('SELECT product_id, product_name, description, price, image_url, stock_quantity FROM products WHERE product_id = ?', [productId]);
        const product = products[0];
        if (!product) {
            return res.status(404).json({ message: 'Product not found.' });
        }
        res.json(product);
    } catch (error) {
        console.error('Error fetching product details:', error);
        res.status(500).json({ message: 'Server error fetching product details.' });
    }
});

// 5. Place an Order (Checkout) (Requires Authentication)
app.post('/api/orders', authenticateToken, async (req, res) => {
    const { items, total } = req.body;
    const userId = req.user.userId; // Get user ID from authenticated token

    if (!items || items.length === 0 || !total) {
        return res.status(400).json({ message: 'Cart items and total are required to place an order.' });
    }

    let connection;
    try {
        connection = await dbConnectionPool.getConnection(); // Get a connection from the pool
        await connection.beginTransaction(); // Start a transaction

        // Validate items and check stock
        for (const item of items) {
            const [productRows] = await connection.execute('SELECT product_name, price, stock_quantity FROM products WHERE product_id = ?', [item.productId]);
            if (productRows.length === 0) {
                throw new Error(`Product with ID ${item.productId} not found.`);
            }
            const product = productRows[0];
            if (item.quantity > product.stock_quantity) {
                throw new Error(`Insufficient stock for ${product.product_name}. Available: ${product.stock_quantity}, Requested: ${item.quantity}`);
            }
            // Optional: Re-validate price at purchase to prevent client-side manipulation
            if (parseFloat(item.priceAtPurchase).toFixed(2) !== parseFloat(product.price).toFixed(2)) {
                 throw new Error(`Price mismatch for ${product.product_name}. Please refresh your cart.`);
            }
        }

        // Insert into orders table
        const [orderResult] = await connection.execute(
            'INSERT INTO orders (user_id, total_amount, order_status) VALUES (?, ?, ?)',
            [userId, total, 'Pending']
        );
        const orderId = orderResult.insertId;

        // Insert into order_items table and update product stock
        for (const item of items) {
            await connection.execute(
                'INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES (?, ?, ?, ?)',
                [orderId, item.productId, item.quantity, item.priceAtPurchase]
            );
            // Decrease stock quantity
            await connection.execute(
                'UPDATE products SET stock_quantity = stock_quantity - ? WHERE product_id = ?',
                [item.quantity, item.productId]
            );
        }

        await connection.commit(); // Commit the transaction
        res.status(201).json({ message: 'Order placed successfully!', orderId: orderId });

    } catch (error) {
        if (connection) {
            await connection.rollback(); // Rollback transaction on error
        }
        console.error('Error placing order:', error);
        res.status(500).json({ message: error.message || 'Server error placing order. Please try again.' });
    } finally {
        if (connection) {
            connection.release(); // Release the connection back to the pool
        }
    }
});

// 6. Get User's Orders (Requires Authentication)
app.get('/api/orders', authenticateToken, async (req, res) => {
    const userId = req.user.userId; // Get user ID from authenticated token

    try {
        const [orders] = await dbConnectionPool.execute(
            'SELECT order_id, total_amount, order_date, order_status FROM orders WHERE user_id = ? ORDER BY order_date DESC',
            [userId]
        );

        // For each order, fetch its items
        const ordersWithItems = await Promise.all(orders.map(async (order) => {
            const [items] = await dbConnectionPool.execute(
                `SELECT oi.quantity, oi.price_at_purchase, p.product_name, p.image_url
                 FROM order_items oi
                 JOIN products p ON oi.product_id = p.product_id
                 WHERE oi.order_id = ?`,
                [order.order_id]
            );
            return { ...order, items: items };
        }));

        res.json(ordersWithItems);
    } catch (error) {
        console.error('Error fetching user orders:', error);
        res.status(500).json({ message: 'Server error fetching user orders.' });
    }
});


// Start the server
app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    await connectToDatabase(); // Connect to DB when server starts
});
