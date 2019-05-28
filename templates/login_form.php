<div id="login-form-container">
  <?php if ( $attributes['show_title'] ) : ?>
    <h2><?php _e( 'Sign In', 'tdp-custom-login' ); ?></h2>
  <?php endif;

  if ( count( $attributes['errors'] ) > 0 ) : ?>
    <?php foreach ( $attributes['errors'] as $error ) : ?>
      <p class="error">
        <?php echo $error; ?>
      </p>
    <?php endforeach;
  endif;

  if ( $attributes['registered'] ) : ?>
    <p class="info">
      <?php
        printf(
          __( 'You have successfully registered to <strong>%s</strong>. We have emailed your password to the email address you entered.', 'tdp-custom-login' ),
          get_bloginfo( 'name' )
        );
      ?>
    </p>
  <?php endif;

  if ( $attributes['lost_password_sent'] ) : ?>
    <p class="info">
      <?php _e( 'Check your email for a link to reset your password.', 'tdp-custom-login' ); ?>
    </p>
  <?php endif;

  if ( $attributes['password_updated'] ) : ?>
    <p class="login-info">
      <?php _e( 'Your password has been changed. You can sign in now.', 'tdp-custom-login' ); ?>
    </p>
  <?php endif; ?>

  <form id="loginform" name="loginform" action="<?php echo wp_login_url(); ?>" method="post">
    <p class="login-username">
      <label for="user_login"><?php _e( 'Email Address', 'tdp-custom-login' ); ?></label>
      <input type="text" name="log" id="user_login">
    </p>
    <p class="login-password">
      <label for="user_pass"><?php _e( 'Password', 'tdp-custom-login' ); ?></label>
      <input type="password" name="pwd" id="user_pass">
    </p>
    <p class="login-remember">
      <label>
        <input id="rememberme" name="rememberme" type="checkbox" value="forever">
        <?php _e( 'Remember Me', 'tdp-custom-login' ); ?>
      </label>
    </p>
    <p class="login-submit">
      <input id="wp-submit" name="wp-submit" type="submit" class="submit button login-button" value="<?php _e( 'Sign In', 'tdp-custom-login' ); ?>">
      <input type="hidden" name="redirect_to" value="<?php echo $attributes['redirect']; ?>">
      <?php if ( $attributes['recaptcha_site_key'] ) : ?>
        <input type="hidden" id="recaptcha-site-key" value="<?php echo $attributes['recaptcha_site_key']; ?>">
        <input type="hidden" id="g-recaptcha-response" name="g-recaptcha-response">
      <?php endif; ?>
    </p>
  </form>

  <a class="register" href="<?php echo esc_url( home_url( '/register/' ) ); ?>">
    <?php _e( 'Register', 'tdp-custom-login' ); ?>
  </a>
  <span class="sep"> | </span>
  <a class="forgot-password" href="<?php echo wp_lostpassword_url(); ?>">
    <?php _e( 'Forgot your password?', 'tdp-custom-login' ); ?>
  </a>
</div>