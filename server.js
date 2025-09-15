    const express = require('express');
    const sqlite3 = require('sqlite3').verbose();
    const bcrypt = require('bcryptjs');
    const jwt = require('jsonwebtoken');
    const cors = require('cors');
    const multer = require('multer'); // Importa multer
    const path = require('path'); // Importa path per gestire i percorsi dei file
    const fs = require('fs'); // Importa fs per gestire il filesystem
    const rateLimit = require('express-rate-limit');
    const helmet = require('helmet');

    const app = express();
    const port = 3000;
    const JWT_SECRET = process.env.JWT_SECRET || 'supersecretjwtkey'; // Usa variabile d'ambiente o fallback

    // --- Configurazione Multer per l'upload delle immagini ---
    const uploadsDir = path.join(__dirname, 'uploads');
    // Crea la cartella 'uploads' se non esiste
    if (!fs.existsSync(uploadsDir)) {
        fs.mkdirSync(uploadsDir);
    }

    const storage = multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, uploadsDir); // Le immagini verranno salvate nella cartella 'uploads'
        },
        filename: function (req, file, cb) {
            // Genera un nome file unico per evitare sovrascritture
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
        }
    });

    const upload = multer({
        storage: storage,
        limits: { fileSize: 5 * 1024 * 1024 }, // Limite di 5MB per file
        fileFilter: (req, file, cb) => {
            const filetypes = /jpeg|jpg|png|gif/;
            const mimetype = filetypes.test(file.mimetype);
            const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

            if (mimetype && extname) {
                return cb(null, true);
            }
            cb(new Error('Solo immagini (jpeg, jpg, png, gif) sono permesse!'));
        }
    });
    // --- Fine Configurazione Multer ---

    // Connessione al database SQLite
    const db = new sqlite3.Database('./bookside.db', (err) => {
        if (err) {
            console.error('Errore connessione database:', err.message);
        } else {
            console.log('Connesso al database SQLite.');
            // Creazione tabelle se non esistono
            db.serialize(() => {
                db.run(`CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )`);
                db.run(`CREATE TABLE IF NOT EXISTS books (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    author TEXT,
                    school TEXT NOT NULL,
                    class TEXT NOT NULL,
                    price TEXT NOT NULL,
                    description TEXT,
                    image TEXT, -- Questo campo ora conterrà il percorso locale dell'immagine
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )`);
                console.log('Tabelle verificate/create.');

                // Inserisci utente admin se non esiste
                db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
                    if (err) {
                        console.error('Errore controllo admin:', err.message);
                    } else if (!row) {
                        bcrypt.hash('admin123', 10, (err, hashedPassword) => {
                            if (err) {
                                console.error('Errore hashing password admin:', err.message);
                            } else {
                                db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', ['admin', 'admin@bookside.com', hashedPassword], function (err) {
                                    if (err) {
                                        console.error('Errore inserimento admin:', err.message);
                                    } else {
                                        console.log('Utente admin creato con successo.');
                                    }
                                });
                            }
                        });
                    } else {
                        console.log('Utente admin già esistente.');
                    }
                });
            });
        }
    });

    // Middleware
    app.use(helmet()); // Security headers
    app.use(cors()); // Abilita CORS per richieste da frontend
    app.use(express.json()); // Per parsare il body delle richieste JSON

    // Rate limiting
    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        message: 'Too many requests from this IP, please try again later.'
    });
    app.use('/api/', limiter);

    // Stricter rate limiting for auth routes
    const authLimiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 5, // limit each IP to 5 requests per windowMs
        message: 'Too many authentication attempts, please try again later.'
    });
    app.use('/api/register', authLimiter);
    app.use('/api/login', authLimiter);

    // --- Servire i file statici (immagini caricate) ---
    app.use('/uploads', express.static(uploadsDir));
    // --- Fine Servire i file statici ---

    // Serve frontend static files
    const frontendDir = path.join(__dirname, '..');
    console.log('Serving frontend files from:', frontendDir);
    app.use(express.static(frontendDir));

    // Serve specific frontend files for routes
    app.get('/', (req, res) => {
        res.sendFile(path.join(frontendDir, 'index.html'));
    });
    app.get('/register.html', (req, res) => {
        res.sendFile(path.join(frontendDir, 'register.html'));
    });
    app.get('/login.html', (req, res) => {
        res.sendFile(path.join(frontendDir, 'login.html'));
    });
    app.get('/chat.html', (req, res) => {
        res.sendFile(path.join(frontendDir, 'chat.html'));
    });
    app.get('/my-books.html', (req, res) => {
        res.sendFile(path.join(frontendDir, 'my-books.html'));
    });
    app.get('/add-book.html', (req, res) => {
        res.sendFile(path.join(frontendDir, 'add-book.html'));
    });
    app.get('/listings.html', (req, res) => {
        res.sendFile(path.join(frontendDir, 'listings.html'));
    });
    app.get('/book-details.html', (req, res) => {
        res.sendFile(path.join(frontendDir, 'book-details.html'));
    });
    app.get('/contact.html', (req, res) => {
        res.sendFile(path.join(frontendDir, 'contact.html'));
    });

    // Middleware per l'autenticazione JWT
    const authenticateToken = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (token == null) return res.status(401).json({ message: 'Token di autenticazione richiesto.' });

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({ message: 'Token non valido o scaduto.' });
            req.user = user;
            next();
        });
    };

    // --- Rotte API ---

    // Registrazione utente
    app.post('/api/register', (req, res) => {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'Tutti i campi sono obbligatori.' });
        }

        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Errore hashing password:', err.message);
                return res.status(500).json({ message: 'Errore durante la registrazione.' });
            }

            db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(409).json({ message: 'Username o Email già in uso.' });
                    }
                    console.error('Errore inserimento utente:', err.message);
                    return res.status(500).json({ message: 'Errore durante la registrazione.' });
                }
                res.status(201).json({ message: 'Registrazione avvenuta con successo!', userId: this.lastID });
            });
        });
    });

    // Login utente
    app.post('/api/login', (req, res) => {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: 'Username e password sono obbligatori.' });
        }

        db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
            if (err) {
                console.error('Errore recupero utente:', err.message);
                return res.status(500).json({ message: 'Errore durante il login.' });
            }
            if (!user) {
                return res.status(401).json({ message: 'Credenziali non valide.' });
            }

            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) {
                    console.error('Errore confronto password:', err.message);
                    return res.status(500).json({ message: 'Errore durante il login.' });
                }
                if (!isMatch) {
                    return res.status(401).json({ message: 'Credenziali non valide.' });
                }

                const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
                res.json({ message: 'Login avvenuto con successo!', token, username: user.username });
            });
        });
    });



    // --- Gestione Libri ---

    // POST /api/books - Aggiungi un nuovo libro (con upload immagine)
    app.post('/api/books', authenticateToken, upload.single('image'), (req, res) => {
        const { title, author, school, class: bookClass, price, description } = req.body;
        const imagePath = req.file ? `/uploads/${req.file.filename}` : null; // Salva il percorso relativo

        if (!title || !school || !bookClass || !price || !description) {
            // Se l'immagine è stata caricata ma la validazione fallisce, eliminala
            if (req.file) {
                fs.unlink(req.file.path, (err) => {
                    if (err) console.error('Errore eliminazione file:', err);
                });
            }
            return res.status(400).json({ message: 'Titolo, scuola, classe, prezzo e descrizione sono obbligatori.' });
        }

        db.run('INSERT INTO books (user_id, title, author, school, class, price, description, image) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [req.user.id, title, author, school, bookClass, price, description, imagePath],
            function (err) {
                if (err) {
                    console.error('Errore inserimento libro:', err.message);
                    // Se l'immagine è stata caricata ma l'inserimento nel DB fallisce, eliminala
                    if (req.file) {
                        fs.unlink(req.file.path, (err) => {
                            if (err) console.error('Errore eliminazione file:', err);
                        });
                    }
                    return res.status(500).json({ message: 'Errore durante l\'aggiunta del libro.' });
                }
                res.status(201).json({ message: 'Libro aggiunto con successo!', bookId: this.lastID, imagePath: imagePath });
            }
        );
    });

    // PUT /api/books/:id - Modifica un libro esistente (con gestione immagine)
    app.put('/api/books/:id', authenticateToken, upload.single('image'), (req, res) => {
        const bookId = req.params.id;
        const { title, author, school, class: bookClass, price, description } = req.body;
        let newImagePath = req.file ? `/uploads/${req.file.filename}` : null;

        if (!title || !school || !bookClass || !price || !description) {
            if (req.file) { // Se un nuovo file è stato caricato ma la validazione fallisce
                fs.unlink(req.file.path, (err) => {
                    if (err) console.error('Errore eliminazione file temporaneo:', err);
                });
            }
            return res.status(400).json({ message: 'Titolo, scuola, classe, prezzo e descrizione sono obbligatori.' });
        }

        db.get('SELECT * FROM books WHERE id = ? AND user_id = ?', [bookId, req.user.id], (err, book) => {
            if (err) {
                console.error('Errore recupero libro per modifica:', err.message);
                return res.status(500).json({ message: 'Errore durante la modifica del libro.' });
            }
            if (!book) {
                return res.status(404).json({ message: 'Libro non trovato o non autorizzato.' });
            }

            // Se è stata caricata una nuova immagine, elimina la vecchia se esiste
            if (newImagePath && book.image) {
                const oldImagePath = path.join(__dirname, book.image);
                fs.unlink(oldImagePath, (err) => {
                    if (err) console.warn('Impossibile eliminare la vecchia immagine:', err);
                });
            } else if (!newImagePath && book.image) {
                // Se non è stata caricata una nuova immagine, ma il campo 'image' è stato svuotato dal frontend
                // (es. l'utente ha rimosso l'URL o il file), allora elimina la vecchia immagine
                // Questo richiede un campo specifico nel body per indicare la rimozione dell'immagine
                // Per semplicità, se newImagePath è null e non c'è req.file, manteniamo la vecchia immagine
                // A meno che il frontend non invii esplicitamente `image: ""`
                if (req.body.image === "") { // Se il frontend ha svuotato il campo immagine
                    const oldImagePath = path.join(__dirname, book.image);
                    fs.unlink(oldImagePath, (err) => {
                        if (err) console.warn('Impossibile eliminare la vecchia immagine:', err);
                    });
                    newImagePath = ""; // Imposta l'immagine a stringa vuota nel DB
                } else {
                    newImagePath = book.image; // Mantiene l'immagine esistente
                }
            }


            db.run('UPDATE books SET title = ?, author = ?, school = ?, class = ?, price = ?, description = ?, image = ? WHERE id = ? AND user_id = ?',
                [title, author, school, bookClass, price, description, newImagePath, bookId, req.user.id],
                function (err) {
                    if (err) {
                        console.error('Errore aggiornamento libro:', err.message);
                        // Se l'aggiornamento nel DB fallisce ma un nuovo file è stato caricato, eliminalo
                        if (req.file) {
                            fs.unlink(req.file.path, (err) => {
                                if (err) console.error('Errore eliminazione file:', err);
                            });
                        }
                        return res.status(500).json({ message: 'Errore durante la modifica del libro.' });
                    }
                    res.json({ message: 'Libro modificato con successo!', imagePath: newImagePath });
                }
            );
        });
    });


    // DELETE /api/books/:id - Elimina un libro
    app.delete('/api/books/:id', authenticateToken, (req, res) => {
        const bookId = req.params.id;

        db.get('SELECT image FROM books WHERE id = ? AND user_id = ?', [bookId, req.user.id], (err, book) => {
            if (err) {
                console.error('Errore recupero immagine libro per eliminazione:', err.message);
                return res.status(500).json({ message: 'Errore durante l\'eliminazione del libro.' });
            }
            if (!book) {
                return res.status(404).json({ message: 'Libro non trovato o non autorizzato.' });
            }

            db.run('DELETE FROM books WHERE id = ? AND user_id = ?', [bookId, req.user.id], function (err) {
                if (err) {
                    console.error('Errore eliminazione libro:', err.message);
                    return res.status(500).json({ message: 'Errore durante l\'eliminazione del libro.' });
                }
                if (this.changes === 0) {
                    return res.status(404).json({ message: 'Libro non trovato o non autorizzato.' });
                }

                // Elimina il file immagine associato se esiste
                if (book.image) {
                    const imageFullPath = path.join(__dirname, book.image);
                    fs.unlink(imageFullPath, (err) => {
                        if (err) console.warn('Impossibile eliminare il file immagine:', err);
                    });
                }
                res.json({ message: 'Libro eliminato con successo!' });
            });
        });
    });

    // GET /api/books - Ottieni tutti i libri con paginazione, filtri e ordinamento
    app.get('/api/books', (req, res) => {
        const { search, school, class: bookClass, sort, page = 1, limit = 6 } = req.query;
        let query = `SELECT b.*, u.username AS seller, u.email AS sellerEmail FROM books b JOIN users u ON b.user_id = u.id WHERE 1=1`;
        let countQuery = `SELECT COUNT(*) AS total FROM books b JOIN users u ON b.user_id = u.id WHERE 1=1`;
        const params = [];
        const countParams = [];

        if (search) {
            query += ` AND (b.title LIKE ? OR b.author LIKE ? OR b.school LIKE ? OR b.class LIKE ?)`;
            countQuery += ` AND (b.title LIKE ? OR b.author LIKE ? OR b.school LIKE ? OR b.class LIKE ?)`;
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm);
            countParams.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }
        if (school) {
            query += ` AND b.school = ?`;
            countQuery += ` AND b.school = ?`;
            params.push(school);
            countParams.push(school);
        }
        if (bookClass) {
            query += ` AND b.class = ?`;
            countQuery += ` AND b.class = ?`;
            params.push(bookClass);
            countParams.push(bookClass);
        }

        // Conteggio totale libri per paginazione
        db.get(countQuery, countParams, (err, row) => {
            if (err) {
                console.error('Errore conteggio libri:', err.message);
                return res.status(500).json({ message: 'Errore durante il recupero dei libri.' });
            }
            const totalBooks = row.total;
            const totalPages = Math.ceil(totalBooks / limit);
            const offset = (page - 1) * limit;

            // Ordinamento
            if (sort) {
                switch (sort) {
                    case 'title_asc': query += ` ORDER BY b.title ASC`; break;
                    case 'title_desc': query += ` ORDER BY b.title DESC`; break;
                    case 'price_asc': query += ` ORDER BY CAST(REPLACE(b.price, '€', '') AS REAL) ASC`; break; // Converti prezzo in numero
                    case 'price_desc': query += ` ORDER BY CAST(REPLACE(b.price, '€', '') AS REAL) DESC`; break;
                    default: query += ` ORDER BY b.id DESC`; // Default
                }
            } else {
                query += ` ORDER BY b.id DESC`; // Default se nessun sort specificato
            }

            query += ` LIMIT ? OFFSET ?`;
            params.push(limit, offset);

            db.all(query, params, (err, books) => {
                if (err) {
                    console.error('Errore recupero libri:', err.message);
                    return res.status(500).json({ message: 'Errore durante il recupero dei libri.' });
                }
                res.json({
                    books,
                    currentPage: parseInt(page),
                    limit: parseInt(limit),
                    totalBooks,
                    totalPages
                });
            });
        });
    });

    // GET /api/books/:id - Ottieni un singolo libro per ID
    app.get('/api/books/:id', (req, res) => {
        const { id } = req.params;
        console.log(`Backend: Richiesta dettagli per libro con ID: ${id}`);
        db.get('SELECT b.*, u.username AS seller, u.email AS sellerEmail FROM books b JOIN users u ON b.user_id = u.id WHERE b.id = ?', [id], (err, row) => {
            if (err) {
                console.error("Errore recupero libro per ID:", err.message);
                return res.status(500).json({ message: 'Errore durante il recupero del libro.' });
            }
            if (!row) {
                console.warn(`Backend: Libro con ID ${id} non trovato.`);
                return res.status(404).json({ message: 'Libro non trovato.' });
            }
            console.log(`Backend: Trovato libro con ID ${id}:`, row.title);
            res.json(row);
        });
    });

    // GET /api/my-books - Ottieni i libri dell'utente autenticato
    app.get('/api/my-books', authenticateToken, (req, res) => {
        const { page = 1, limit = 6 } = req.query;
        const userId = req.user.id;

        let countQuery = `SELECT COUNT(*) AS total FROM books WHERE user_id = ?`;
        let query = `SELECT * FROM books WHERE user_id = ? ORDER BY id DESC`;
        const params = [userId];
        const countParams = [userId];

        db.get(countQuery, countParams, (err, row) => {
            if (err) {
                console.error('Errore conteggio miei libri:', err.message);
                return res.status(500).json({ message: 'Errore durante il recupero dei tuoi libri.' });
            }
            const totalBooks = row.total;
            const totalPages = Math.ceil(totalBooks / limit);
            const offset = (page - 1) * limit;

            query += ` LIMIT ? OFFSET ?`;
            params.push(limit, offset);

            db.all(query, params, (err, books) => {
                if (err) {
                    console.error('Errore recupero miei libri:', err.message);
                    return res.status(500).json({ message: 'Errore durante il recupero dei tuoi libri.' });
                }
                res.json({
                    books,
                    currentPage: parseInt(page),
                    limit: parseInt(limit),
                    totalBooks,
                    totalPages
                });
            });
        });
    });

    // --- Gestione Profilo Utente ---

    // GET /api/profile - Ottieni il profilo dell'utente autenticato
    app.get('/api/profile', authenticateToken, (req, res) => {
        db.get('SELECT id, username, email FROM users WHERE id = ?', [req.user.id], (err, user) => {
            if (err) {
                console.error('Errore recupero profilo:', err.message);
                return res.status(500).json({ message: 'Errore durante il recupero del profilo.' });
            }
            if (!user) {
                return res.status(404).json({ message: 'Utente non trovato.' });
            }
            res.json(user);
        });
    });

    // PUT /api/profile - Aggiorna il profilo dell'utente autenticato
    app.put('/api/profile', authenticateToken, (req, res) => {
        const { username, email } = req.body;
        if (!username || !email) {
            return res.status(400).json({ message: 'Username e email sono obbligatori.' });
        }

        // Verifica se username o email sono già in uso da un altro utente
        db.get('SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?', [username, email, req.user.id], (err, existing) => {
            if (err) {
                console.error('Errore verifica unicità:', err.message);
                return res.status(500).json({ message: 'Errore durante la verifica.' });
            }
            if (existing) {
                return res.status(409).json({ message: 'Username o email già in uso.' });
            }

            // Aggiorna il profilo
            db.run('UPDATE users SET username = ?, email = ? WHERE id = ?', [username, email, req.user.id], function (err) {
                if (err) {
                    console.error('Errore aggiornamento profilo:', err.message);
                    return res.status(500).json({ message: 'Errore durante l\'aggiornamento del profilo.' });
                }
                res.json({ message: 'Profilo aggiornato con successo!', username, email });
            });
        });
    });


    // Avvio del server
    app.listen(port, () => {
        console.log(`Server backend in ascolto su http://localhost:${port}`);
    });
    