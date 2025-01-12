// express asyncErrors tem sempre que vir primeiro
require("express-async-errors")

//banco de dados import
const migrationsRun = require("./database/sqlite/migrations");
const AppError = require("./utils/appError");

//importar express
const express = require("express");

const routes = require("./Routes");


//inicializar o express

migrationsRun();

const app = express();
app.use(express.json());
app.use(routes)

app.use((error, request, response, next) => {
    if (error instanceof AppError) {
        return response.status(error.statusCode).json({
            status: "error",
            message: error.message
        });
    }

    console.error(error);

    return response.status(500).json({
        status: "error",
        message: "Internal Error"
    });
});

const PORT = 3333;
app.listen(PORT, () => console.log(`Server is Runnin on Port ${PORT}`));