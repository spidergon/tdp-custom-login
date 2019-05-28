grecaptcha.ready(() => {
  const recaptchaSiteKey = document.getElementById('recaptcha-site-key')
  const gRecaptchaResponse = document.getElementById('g-recaptcha-response')
  if (recaptchaSiteKey && gRecaptchaResponse) {
    grecaptcha
      .execute(recaptchaSiteKey.value, { action: 'login' })
      .then(token => (gRecaptchaResponse.value = token))
  }
})
