<div id="password-lost-form" class="widecolumn">
  <?php if ( $attributes['show_title'] ) : ?>
    <h3><?php _e( 'Forgot Your Password?', 'tdp-custom-login' ); ?></h3>
  <?php endif;

  if ( count( $attributes['errors'] ) > 0 ) : ?>
    <?php foreach ( $attributes['errors'] as $error ) : ?>
      <p class="error">
        <?php echo $error; ?>
      </p>
    <?php endforeach;
  endif; ?>

  <p class="note">
    <?php
      _e(
        'Please enter your email address. You will receive a link to create a new password via email.',
        'tdp-custom-login'
      );
    ?>
  </p>

  <form id="lostpasswordform" action="<?php echo wp_lostpassword_url(); ?>" method="post">
    <p class="form-row">
      <label for="user_login"><?php _e( 'Email Address', 'tdp-custom-login' ); ?>
      <input type="email" name="user_login" id="user_login" required>
    </p>
    <p class="lostpassword-submit">
      <input type="submit" name="submit" class="submit button lostpassword-button"
        value="<?php _e( 'Reset Password', 'tdp-custom-login' ); ?>"/>
      <?php if ( $attributes['recaptcha_site_key'] ) : ?>
        <input type="hidden" id="recaptcha-site-key" value="<?php echo $attributes['recaptcha_site_key']; ?>">
        <input type="hidden" id="g-recaptcha-response" name="g-recaptcha-response">
      <?php endif; ?>
    </p>
  </form>

  <a class="login" href="<?php echo esc_url( home_url( '/login/' ) ); ?>">
    <?php _e( 'Sign In', 'tdp-custom-login' ); ?>
  </a>
  <span class="sep"> | </span>
  <a class="register" href="<?php echo esc_url( home_url( '/register/' ) ); ?>">
    <?php _e( 'Register', 'tdp-custom-login' ); ?>
  </a>
</div>