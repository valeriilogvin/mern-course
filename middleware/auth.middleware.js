/*
* middleware - это обычная функция,
* которая позволяет перехватывать определенные данные
* и делать логику, которую мы опишем
* */

const jwt = require('jsonwebtoken') // библиотека для раскодирования токена
const config = require('config')

module.exports = (req, res, next) => { // next - позволяет продолжить выполнение запроса

    // базавая проверка
    // проверяет доступность сервера
    if(req.method === 'OPTIONS'){
        return next()
    }

    // если это обычный запрос (post или get) то мы будем выполнять
    // обычный запрос в боке ↓
    try {
        const token = req.headers.authorization.split(' ')[1] // "Bearer TOKEN"

        // если нет токена
        if(!token){
            return res.status(401).json({message: 'Нет авторизации'})
        }

        const decoded = jwt.verify(token, config.get('jwtSecret'))
        req.user = decoded
        next()

    } catch (e) {
        res.status(401).json({message: 'Нет авторизации'})
    }
}