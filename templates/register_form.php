<div id="register-form-container" class="widecolumn">
  <?php if ( $attributes['show_title'] ) : ?>
    <h3><?php _e( 'Register', 'tdp-custom-login' ); ?></h3>
  <?php endif;

  if ( count( $attributes['errors'] ) > 0 ) :
    foreach ( $attributes['errors'] as $error ) : ?>
      <p class="error">
        <?php echo $error; ?>
      </p>
    <?php endforeach;
  endif; ?>

  <form id="signupform" action="<?php echo wp_registration_url(); ?>" method="post">
    <p class="form-row">
      <label for="email"><?php _e( 'Email Address', 'tdp-custom-login' ); ?> <strong>*</strong></label>
      <input type="email" name="email" id="email" required>
    </p>
    <p class="form-row">
      <label for="first_name"><?php _e( 'First name', 'tdp-custom-login' ); ?></label>
      <input type="text" name="first_name" id="first-name">
    </p>
    <p class="form-row">
      <label for="last_name"><?php _e( 'Last name', 'tdp-custom-login' ); ?></label>
      <input type="text" name="last_name" id="last-name">
    </p>
    <p class="form-row note">
      <?php _e( 'Your password will be generated automatically and sent to your email address.', 'tdp-custom-login' ); ?>
    </p>
    <p class="signup-submit">
      <input type="submit" name="submit" class="submit button register-button" value="<?php _e( 'Register', 'tdp-custom-login' ); ?>"/>
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
  <a class="forgot-password" href="<?php echo wp_lostpassword_url(); ?>">
    <?php _e( 'Forgot your password?', 'tdp-custom-login' ); ?>
  </a>
</div>