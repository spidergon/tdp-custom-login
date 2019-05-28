<div id="password-reset-form" class="widecolumn">
  <?php if ( $attributes['show_title'] ) : ?>
    <h3><?php _e( 'Pick a New Password', 'tdp-custom-login' ); ?></h3>
  <?php endif; ?>

  <form name="resetpassform" id="resetpassform" action="<?php echo site_url( 'wp-login.php?action=resetpass' ); ?>" method="post" autocomplete="off">
    <input type="hidden" id="user_login" name="rp_login" value="<?php echo esc_attr( $attributes['login'] ); ?>" autocomplete="off" />
    <input type="hidden" name="rp_key" value="<?php echo esc_attr( $attributes['key'] ); ?>" />

    <?php if ( count( $attributes['errors'] ) > 0 ) :
      foreach ( $attributes['errors'] as $error ) : ?>
        <p class="error">
          <?php echo $error; ?>
        </p>
      <?php endforeach;
    endif; ?>

    <p>
      <label for="pass1"><?php _e( 'New password', 'tdp-custom-login' ) ?></label>
      <input type="password" name="pass1" id="pass1" class="input" size="20" value="" autocomplete="off" required />
    </p>
    <p>
      <label for="pass2"><?php _e( 'Confirm new password', 'tdp-custom-login' ) ?></label>
      <input type="password" name="pass2" id="pass2" class="input" size="20" value="" autocomplete="off" required />
    </p>

    <p class="note"><?php echo wp_get_password_hint(); ?></p>

    <p class="resetpass-submit">
      <input type="submit" name="submit" id="resetpass-button"
        class="submit button resetpass-button" value="<?php _e( 'Reset Password', 'tdp-custom-login' ); ?>" />
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