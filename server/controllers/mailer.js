import nodemailer from 'nodemailer';
import Mailgen from 'mailgen';

import ENV from '../config.js';

// https://ethereal.email/create
let nodeConfig = {
    host: "smtp.ethereal.email",
    port: 587,
    secure: false, // Use `true` for port 465, `false` for all other ports
    auth: {
        user: ENV.EMAIL,
        pass: ENV.PASSWORD,
    }
}

let transporter = nodemailer.createTransport(nodeConfig);

let MailGenerator = new Mailgen({
    theme: "default",
    product: {
        name: "Mailgen",
        link: 'https://mailgen.js/'
    }
})

/** POST: http://localhost:8080/api/registerMail 
 * @param: {
 *   "username" : "example123",
 *   "userEmail" : "admin123",
 *   "text" : "",
 *   "subject" : ""
 * }
 */
export const registerMail = async (req, res) => {
    const { username, userEmail, text, subject } = req.body;

    // Body of the email
    var email = {
        body: {
            name: username,
            intro: text || 'Welcome to Daily Tuition! We\'re very excited to have you on board.',
            outro: 'Need help, or have questions? Just reply to this email, we\'d love to help.'
        }
    }
    var emailBody = MailGenerator.generate(email);

    let message = {
        from: ENV.EMAIL,
        to: userEmail,
        subject: subject || "Signup Successful",
        html: emailBody
    }
    // Send mail
    transporter.sendMail(message)
        .then(() => {
            return res.status(200).send({ message: "You should receive an email from us." })
        })
        .catch(error => res.status(500).send({ error }))
}
