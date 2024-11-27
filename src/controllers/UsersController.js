
const { hash, compare } = require('bcryptjs')
const AppError = require('../utils/appError');

const sqliteConnection = require('../database/sqlite');

class UsersController {

    // **Um Controller pode ter apenas 5 metodos

    // *index - GET para listar varios registros
    // *show - GET para exibir um registro específico
    // *create - POST para criar um registro
    async create(request, response) {

        const { name, email, password } = request.body;
        const database = await sqliteConnection();
        const checkUserExists = await database.get("SELECT * FROM users WHERE email = (?)", [email])

        if (checkUserExists) {
            throw new AppError("este e-mail ja está em uso.");
        }

        const hashedPassword = await hash(password, 7)

        await database.run("INSERT INTO users (name, email, password) VALUES (?,?,?) ",
            [name, email, hashedPassword]);

        return response.status(201).json();
    }

    // *update - PUT para atualizar um registro
    async update(request, response) {
        const { name, email, password, old_password } = request.body;
        const { id } = request.params;
        const database = await sqliteConnection();
        const user = await database.get("SELECT * FROM users WHERE id = (?)", [id]);
        if (!user) {
            throw new AppError('Usuário não encontrado')
        }

        const checkUserNewEmail = await database.get("SELECT * FROM users WHERE email = (?)", [email]);
        if (checkUserNewEmail && checkUserNewEmail.id !== id) {
            throw new AppError('Email já está em uso')
        }

        const hashedPassword = await hash(password, 7)
        user.name = name ?? user.name;
        user.email = email ?? user.email;

        if(password && !old_password){
            throw new AppError("Senha antiga necessária")
        }

        if(password && old_password){
            const checkOldPasswordMatch = await compare( old_password , user.password)

            if(!checkOldPasswordMatch){
                throw new AppError("Senha Antiga Não confere.")
            }

            user.password = await hash(password, 7)
        }


        await database.run(`UPDATE users SET
            name = ?,
            email = ?,
            password = ?, 
            updated_at = DATETIME ('now', 'localtime')
            WHERE id = ?`,
            [user.name, user.email,user.password, id]
        );

        return response.json({
            message: "Usuario atualizado"
        });

    }


    // *delete - DELETE para remover um registro

}



module.exports = UsersController;