
function sanitizeContent(content) {
    if (typeof content === 'string') {
        return DOMPurify.sanitize(content);
    } else if (window?.jQuery && content instanceof window.jQuery) {
        const originalHtml = content.prop('outerHTML');
        const sanitizedHtml = DOMPurify.sanitize(originalHtml);
        if (sanitizedHtml !== originalHtml) {
            throw new Error("The content contains potentially unsafe HTML.");
        }
    }
    return content;
}
function follow(user) {
    $.ajax({
        type: 'POST',
        url: 'JWT/final/follow/' + user
    }).then(function (result) {
        $("#toast").append(sanitizeContent(result));
    })
}
