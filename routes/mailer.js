const formData = require('form-data');
const Mailgun = require('mailgun.js');
const mailgun = new Mailgun(formData);
const mg = mailgun.client({ 
    username: 'api', 
    key: process.env.MAILGUN_API_KEY 
});

const sendContactUsEmail = (contactDetails) => {
    const messageData = {
        from: 'thevintagegaragetest@gmail.com',
        to: 'ajgabl18@gmail.com',
        subject: 'New Contact Us Message',
        text: `You have received a new message from ${contactDetails.name} (${contactDetails.email}):\n\n${contactDetails.message}`
    };

    return mg.messages.create(process.env.MAILGUN_DOMAIN, messageData);
};

const sendReferralEmail = (referralDetails) => {
    const messageData = {
        from: 'thevintagegaragetest@gmail.com',
        to: 'ajgabl18@gmail.com',
        subject: 'New Referral Message',
        text: `You have received a new referral from ${referralDetails.organisation} (${referralDetails.email}):\n\n${referralDetails.message}`
    };

    return mg.messages.create(process.env.MAILGUN_DOMAIN, messageData);
};

const sendOrderConfirmationEmail = (email, orderDetails) => {
    const messageData = {
        from: 'thevintagegaragetest@gmail.com',
        to: email,
        subject: 'Order Confirmation',
        text: `Thank you for your purchase!\n\n${orderDetails}`
    };

    return mg.messages.create(process.env.MAILGUN_DOMAIN, messageData);
};

const sendOrderNotificationEmail = (email, orderDetails) => {
    const messageData = {
        from: 'thevintagegaragetest@gmail.com',
        to: email,
        subject: 'New Order Received',
        text: `A new order has been placed:\n\n${orderDetails}`
    };

    return mg.messages.create(process.env.MAILGUN_DOMAIN, messageData);
};

module.exports = {
    sendContactUsEmail,
    sendReferralEmail,
    sendOrderConfirmationEmail,
    sendOrderNotificationEmail
};
