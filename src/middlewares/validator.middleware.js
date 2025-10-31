export const validateSchema = (schema) => (req, res, next) => {
   
    try {
            schema.parse(req.body);
            next();
    } catch (error) {
        // Creamos un objeto para mapear los errores
        const errorMessages = {};
        
        error.issues.forEach(issue => {
            // issue.path[0] será 'password' o 'email', etc.
            const field = issue.path[0];
            const message = issue.message;
            
            errorMessages[field] = message;
        });

        return res.status(400).json(errorMessages);
    }
}