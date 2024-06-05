require('dotenv').config();
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sendEmail = (to, subject, text, html) => {
    const msg = {
        to,
        from: process.env.EMAIL_USER, // Your verified SendGrid sender email
        subject,
        text,
        html,
    };

    return sgMail.send(msg);
};

const sendContactUsEmail = (contactDetails) => {
    const subject = 'New Contact Us Message';
    const text = `You have received a new message from ${contactDetails.name} (${contactDetails.email}):\n\n${contactDetails.message}`;
    const html = `<p>You have received a new message from ${contactDetails.name} (${contactDetails.email}):</p><p>${contactDetails.message}</p>`;
    return sendEmail('ajgabl18@gmail.com', subject, text, html);
};

const sendReferralEmail = (referralDetails) => {
    const subject = 'New Referral Message';
    const text = `You have received a new referral from ${referralDetails.organisation} (${referralDetails.email}):\n\n${referralDetails.message}`;
    const html = `<p>You have received a new referral from ${referralDetails.organisation} (${referralDetails.email}):</p><p>${referralDetails.message}</p>`;
    return sendEmail('ajgabl18@gmail.com', subject, text, html);
};

const sendOrderConfirmationEmail = (email, orderDetails) => {
    const subject = 'Order Confirmation';
    const text = `Thank you for your purchase!\n\n${orderDetails}\n\n Your order is being shipped as soon as possible!\n If you selected pickup, please email us at wegiveshare@gmail.com to arrange a time to pick up your order.`;
    const html = `<p>Thank you for your purchase!</p><p>${orderDetails.replace(/\n/g, '<br>')}</p><p>Your order is being shipped as soon as possible!</p><p>If you selected pickup, please email us at <a href="mailto:wegiveshare@gmail.com">wegiveshare@gmail.com</a> to arrange a time to pick up your order.</p>`;
    return sendEmail(email, subject, text, html);
};

const sendOrderNotificationEmail = (email, orderDetails, customerDetails) => {
    const subject = 'New Order Received';
    const text = `A new order has been placed:\n\n${orderDetails}\n\n Customer Details:\n ${customerDetails}`;
    const html = `<p>A new order has been placed:</p><p>${orderDetails.replace(/\n/g, '<br>')}</p><p>Customer Details:</p><p>${customerDetails.replace(/\n/g, '<br>')}</p>`;
    return sendEmail(email, subject, text, html);
};

module.exports = {
    sendContactUsEmail,
    sendReferralEmail,
    sendOrderConfirmationEmail,
    sendOrderNotificationEmail
};
