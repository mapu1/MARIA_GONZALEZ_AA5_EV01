const bcrypt = require('bcrypt');

// Controlador para la página de inicio de sesión
function login(req, res) {
    // Si el usuario no está autenticado, renderiza la página de inicio de sesión
    if (req.session.loggedin != true) {
        res.render('login/index');
    } else {
        // Si el usuario ya está autenticado, redirige a la página principal
        res.redirect('/');
    }
}

// Controlador para autenticar al usuario
function auth(req, res) {
    const data = req.body; // Aquí se obtiene los datos del cuerpo de la solicitud
    req.getConnection((err, conn) => {
        // Consulta la base de datos para encontrar el usuario por email
        conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userdata) => {
            if (userdata.length > 0) {
                // Si el usuario existe, verifica la contraseña
                userdata.forEach(element => {
                    bcrypt.compare(data.password, element.password, (err, isMatch) => {
                        if (!isMatch) {
                            // Si la contraseña no coincide, renderiza la página de inicio de sesión con un error
                            res.render('login/index', { error: 'Error: Contraseña incorrecta!' });
                        } else {
                            // Si la contraseña coincide, establece la sesión del usuario y redirige a la página principal
                            req.session.loggedin = true;
                            req.session.name = element.name;
                            res.redirect('/');
                        }
                    });
                });
            } else {
                // Si el usuario no existe, renderiza la página de inicio de sesión con un error
                res.render('login/index', { error: 'Error: El usuario no existe!' });
            }
        });
    });
}

// Controlador para la página de registro
function register(req, res) {
    // Si el usuario no está autenticado, renderiza la página de registro
    if (req.session.loggedin != true) {
        res.render('login/register');
    } else {
        // Si el usuario ya está autenticado, redirige a la página principal
        res.redirect('/');
    }
}

// Controlador para almacenar un nuevo usuario en la base de datos
function storeUser(req, res) {
    const data = req.body; // Obtiene los datos del cuerpo de la solicitud

    req.getConnection((err, conn) => {
        // Consulta la base de datos para verificar si el email ya está registrado
        conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userdata) => {
            if (userdata.length > 0) {
                // Si el usuario ya existe, renderiza la página de registro con un error
                res.render('login/register', { error: 'Error: El usuario ya existe!' });
            } else {
                // Si el usuario no existe, hashea la contraseña y guarda el usuario en la base de datos
                bcrypt.hash(data.password, 12).then(hash => {
                    data.password = hash;

                    req.getConnection((err, conn) => {
                        // Inserta el nuevo usuario en la base de datos
                        conn.query('INSERT INTO users SET ?', [data], (err, rows) => {
                            res.redirect('/');
                        });
                    });
                });
            }
        });
    });
}

// Controlador para cerrar sesión
function logout(req, res) {
    // Si el usuario está autenticado, destruye la sesión
    if (req.session.loggedin == true) {
        req.session.destroy();
    }
    // Redirige a la página de inicio de sesión
    res.redirect('/login');
}

// Exporta los controladores
module.exports = {
    login,
    register,
    storeUser,
    auth,
    logout,
}
