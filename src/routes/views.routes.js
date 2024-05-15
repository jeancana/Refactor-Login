import { Router } from 'express'
import { ProductsController } from '../controllers/product.controller.mdb.js'
import { CartController } from '../controllers/cart.controller.mdb.js'


// Importamos la funciones authToken para validar el token
import { authToken } from '../utils.js'


const router = Router()
const prdController = new ProductsController()
const cartController = new CartController()


// 1) Endpoint que renderiza Presentacion Proyecto Backend 
router.get('/', (req, res) => {

    // Renderizando la plantilla
    res.render('index', {
        title: 'Presentacion Proyecto Backend Coder'
    })

    // http://localhost:5000/

})


// 2) Ruta Renderiza el formulario de Registro de un Nuevo Usuario  
router.get('/register', async (req, res) => {

    // Acomodar esto y pasarlo a JWT
    if (req.session.user) {
        return res.redirect('/products')
    }

    const context = {}
    const errors = req.query.errors

    if (errors) {
        context.errors = JSON.parse(atob(errors))
    }

    res.render('register', context)// El objeto de parámetros pasamos el context.

    //----- Rutas para USAR del Lado del cliente -----------
    // Para mostrar: http://localhost:5000/register 
})

 
// 3) Endpoint para Renderiza TODOS los Productos Paginados 
router.get('/products', authToken, async (req, res) => {

    //console.log('views-PRODUCTS', req.credentials) // Esta Credencial proviene del middleware "authToken"
    //console.log('views-PRODUCTS-2', req.query) // Verificando que viene por el req.query
   
    const { page, access_token } = req.query;
    
    
    const user = req.credentials.payload.username;
    
    // Si existen las Credenciales/Payload del usuario Mostramos la Vista de los productos
    if (req.credentials.payload) {
        
        const products = await prdController.getProducts(10, page)
        //console.log(products.page )
        
        // Renderizando la plantilla de Productos
        res.render('productList', {
            title: 'List Products',
            user: user,
            cartId: '',
            products: products.docs, //Aca asigno toda la lista de productos paginados
            accessToken: access_token,//Estoy pasando el token al cliente
            pagination: {
                prevPage: products.prevPage,
                nextPage: products.nextPage,
                // Aqui se convierte un numero N a un arreglo [1,...,N]
                pages: Array.from({ length: products.totalPages }, (_, i) => i + 1),
                page: products.page,
            }

        })

    } else {

        // sino volvemos al login 
        // Usamo el .redirect() para enviarlo a la plantilla de login
        res.redirect('/login')
   
    }
    

})


// 4) Endpoint para Renderizar un Carrito Especifico y Mostras los productos incluidos dentro del Carrito
router.get('/carts/:cid', async (req, res) => {

    console.log(req.params)

    // Desestructuramos lo que nos llega req.params
    const { cid } = req.params
    //console.log("aca", { cid })

    const cart = await cartController.getCartById(cid)

    console.log("aca cart", cart.products)


    // Renderizando la plantilla 
    res.render('carts', {

        title: 'Unique Cart',
        cartId: cart.id,
        products: cart.products,
        total: cart.total

    })

})


// 5) Endpoint Renderiza el formulario de login de un Usuario
router.get('/login' , async (req, res) => {

    
    // Verificando que viene por req.session.user
    //console.log('views-LOGIN -----> ', req.credentials)

    // Si el usuario tiene Credenciales sigue
    if (req.credentials) {

        console.log('views-LOGIN 2 -----> ', req.credentials)
        
        // como la sesion esta ACTIVA redirecciono la ruta http://localhost:5000/products para que muestre el listo de productos

        res.redirect('/products')

    } else {

        // Como NO esta Activa la Sesion Renderizo la ruta http://localhost:5000/login 
        // Importante: El objeto de parámetros está vacío no necesita datos para enviar, estamos RENDERIZANDO ".render()" la ruta PROPIA Y NO REDIGIENDO a otra, 
        res.render('login', {})

    }

    //----- Rutas para USAR del Lado del cliente -----------
    // Para mostrar: http://localhost:5000/login 
})


// 6) Endpoint Destruir la sesion del usuario y rediccionar al formulario de login
router.get('/logout', async (req, res) => {
    
    req.session.destroy((err) => {

        // Si existe un error en proceso de logout lo reporto 
        if (err) {

            res.status(500).send({ status: 'ERR', data: err.message })

            // Sino devuelvo el mensaje exitoso
        } else {

            // Respuesta vieja 
            //res.status(200).send({ status: 'OK', data: 'Sesión finalizada' })

            // Al cerrar la session redirecciono a la "/login"
            res.redirect("/login")

        }
    })
})


// 7) Endpoint que renderiza la plantilla /chat para probar el chat websockets
router.get('/chat', (req, res) => {

    // Renderizando la plantilla /chat
    res.render('chat', {
        title: 'Chat BackendCoder'
    })

    // http://localhost:5000/chat

})


// 8) Ruta  Mostrar restaurar el password de un Usuario 
router.get('/restore', async (req, res) => {

    if (req.session.user) {

        res.redirect('/profile')

    } else {

        // IMPORTANTE
        // Aca estoy capturando el res.redirect(`/restore?error=1`) que viene por el req.query el ? === . en obj
        const passUpdate = req.query.passUpdate // dato que viene como error se lo asigno a la constante creada

        // Verificando el error que viene de "/api/sessions/login"
        console.log('/api/sessions/restore-passUpdate:', req.query)

        // Como NO esta Activa la Sesion Renderizo la ruta http://localhost:5000/login - hace un Get asi mismo 
        // Importante: El objeto de parámetros envio el objeto { errorMessage } 
        // que sera capturado por handlebars en la vista '/login'
        res.render('restore', {

            // IMPORTANTE: esta la variable que toma HANDLEBARS para mostrar el error =  {{#if errorMessage}}
            updateMessage: passUpdate

        })


    }
})


export default router