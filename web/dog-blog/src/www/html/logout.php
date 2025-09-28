<?php

require_once '../lib/bootstrap.php';

dog_session_start();

unset($_SESSION['username']);

dog_session_end();

require '../tmpl/login.tmpl.php';