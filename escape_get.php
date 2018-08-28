<?


#--------------------------------------------------------------------------------------------------------
# BEGIN : XSS ����
#--------------------------------------------------------------------------------------------------------
/*
    @Function
        mixed filter_input_array ( int $type [, mixed $definition [, bool $add_empty = TRUE ]] )
    @Parameters
        $type : INPUT_GET, INPUT_POST, INPUT_COOKIE, INPUT_SERVER, INPUT_ENV.
        $definition :
            ���ͻ�� : http://php.net/manual/en/filter.constants.php
                    FILTER_SANITIZE_ENCODED
                    FILTER_VALIDATE_INT
                    FILTER_REQUIRE_ARRAY
                    FILTER_REQUIRE_SCALAR
    @ReturnValues

*/

$_GET = filter_input_array(INPUT_GET, FILTER_SANITIZE_STRING);
$_POST = filter_input_array(INPUT_POST, FILTER_SANITIZE_STRING);

# ��� GET ������ ���� HTML�� �����Ѵ�.
$_GET = array_map('htmlspecialchars', $_GET);


#--------------------------------------------------------------------------------------------------------
# END : XSS ����
#--------------------------------------------------------------------------------------------------------





#--------------------------------------------------------------------------------------------------------
# BEGIN : SQL INJECTION ���� : $_POST $_GET ������ stripslashes() ���ش�.
#--------------------------------------------------------------------------------------------------------
/*
    php.ini�� magic_quotes_gpc = On �� ���
    GPC ���������� �ڵ����� �����ð� �پ�´�.
    �̸� ������ �� mysql_real_escape_string() �� ����Ѵ�.
    ����������Լ�(_stripslashes, _mysql_real_escape_string)�� library.php���� ����Ǿ���.
*/

if( get_magic_quotes_gpc() ) {
    $_POST = _stripslashes($_POST);
}
$_POST = array_map('_mysql_real_escape_string', $_POST);



if( get_magic_quotes_gpc() ) {
    $_GET = _stripslashes($_GET);
}
$_GET = array_map('_mysql_real_escape_string', $_GET);


#--------------------------------------------------------------------------------------------------------
# END : SQL INJECTION ���� : $_POST, $_GET ������ stripslashes() ���ش�.
#--------------------------------------------------------------------------------------------------------





#--------------------------------------------------------------------------------------------------------
# BEGIN : SQL INJECTION ���� : Ư�����ڸ� ����ó���Ѵ�.
#--------------------------------------------------------------------------------------------------------
/*
    GET ������ ���Ǵ� ���� ���ڿ� �̿��� Ư�����ڴ� ��� ����ó���Ѵ�.

	���� ���ĺ� : a-z, A-Z
	���� : 0-9
	�ѱ� : \x80-\xff
	��Ÿ : ������ -, ����� _, �ۼ�Ʈ��ȣ %, ��ħǥ . ��ǥ ,
	* �ۼ�Ʈ��ȣ�� urlencode �Ǵ� ���ڿ�(�ѱ�,���� ��)�� �ʿ���

    �������� : ���Խ� ������ �ùٸ��� �۵��ϴ°�?
    �׻� ������ �Ǵ� ���� �Ʒ�ó�� URL�� �Ķ���Ϳ� ������ ����̴�.
    : /login.php?url=%2Fre%2Frelation%2Frelation_regist.php
    ���丮 ������(/)�� ���ڵ��ϸ� %2F �ε�, �ۼ�Ʈ��ȣ�� �����ϸ� �� ���ڵ� ���� �ɷ�����.

*/

$is_run_sqlx = false;

if($is_run_sqlx && $_GET) {
	foreach($_GET as $key=>$val) {
		//$pattern = "/^[a-zA-Z0-9\x80-\xff-_.,#+%]+$/";
		$pattern = "/^[-a-zA-Z0-9\x80-\xff_\s]*$/";

		if( _preg_match($pattern,$key) ) {
		} else {
            header("Content-type: text/html; charset=utf-8");
			echo "<script>alert('URL ��û�� �ùٸ��� ���� ���� ���ԵǾ� �ֽ��ϴ�.(".__LINE__.")   '); history.back(); </script>\n";
			exit;
		}

		if( _preg_match($pattern,$val) ) {
		} else {
            header("Content-type: text/html; charset=utf-8");
			echo "<script>alert('URL ��û�� �ùٸ��� ���� ���� ���ԵǾ� �ֽ��ϴ�.(".__LINE__.")   '); history.back(); </script>\n";
			exit;
		}
	}
}

#--------------------------------------------------------------------------------------------------------
# END : SQL INJECTION ���� : Ư�����ڸ� ����ó���Ѵ�.
#--------------------------------------------------------------------------------------------------------





#--------------------------------------------------------------------------------------------------------
# BEGIN : ���� ����
#--------------------------------------------------------------------------------------------------------
/*
    ���� ����ϴ� GET ������ ��� �������͸� ����Ѵ�.
*/

# �Խ��� / ����Ʈ ���� : ������ �ѹ�
if($_GET['page']) {
    $val = $_GET['page'];
    $pattern = "/^[0-9]*$/";
    if( _preg_match($pattern,$val) ) {
    } else {
        header("Content-type: text/html; charset=utf-8");
        echo "<script>alert('URL ��û�� �ùٸ��� ���� ���� ���ԵǾ� �ֽ��ϴ�.(".__LINE__.")   '); history.back(); </script>\n";
        exit;
    }
}

# �Խ���
if(_page=="3") {
    # �Խ��� �з��ڵ�
    if($_GET['ct']) {
        $val = $_GET['ct'];
        $pattern = "/^[A-Z]*$/";
        if( _preg_match($pattern,$val) ) {
        } else {
            header("Content-type: text/html; charset=utf-8");
            echo "<script>alert('URL ��û�� �ùٸ��� ���� ���� ���ԵǾ� �ֽ��ϴ�.(".__LINE__.")   '); history.back(); </script>\n";
            exit;
        }
    }

    # �Խ��� ������ȣ
    if($_GET['no']) {
        $val = $_GET['no'];
        $pattern = "/^[0-9]*$/";
        if( _preg_match($pattern,$val) ) {
        } else {
            header("Content-type: text/html; charset=utf-8");
            echo "<script>alert('URL ��û�� �ùٸ��� ���� ���� ���ԵǾ� �ֽ��ϴ�.(".__LINE__.")   '); history.back(); </script>\n";
            exit;
        }
    }
    # �Խ��� ������ȣ
    if($_GET['num']) {
        $val = $_GET['num'];
        $pattern = "/^[0-9]*$/";
        if( _preg_match($pattern,$val) ) {
        } else {
            header("Content-type: text/html; charset=utf-8");
            echo "<script>alert('URL ��û�� �ùٸ��� ���� ���� ���ԵǾ� �ֽ��ϴ�.(".__LINE__.")   '); history.back(); </script>\n";
            exit;
        }
    }
}


# ���ͳ� ȫ��
if(_page=="5") {

    # ȫ�� ���й�ȣ
    if($_GET['keykind']) {
        $val = $_GET['keykind'];
        $pattern = "/^[0-9]*$/";
        if( _preg_match($pattern,$val) ) {
        } else {
            header("Content-type: text/html; charset=utf-8");
            echo "<script>alert('URL ��û�� �ùٸ��� ���� ���� ���ԵǾ� �ֽ��ϴ�.(".__LINE__.")   '); history.back(); </script>\n";
            exit;
        }
    }

    # ȫ�� ���й�ȣ
    if($_GET['keykind']) {
        $val = $_GET['keykind'];
        $pattern = "/^[0-9]*$/";
        if( _preg_match($pattern,$val) ) {
        } else {
            header("Content-type: text/html; charset=utf-8");
            echo "<script>alert('URL ��û�� �ùٸ��� ���� ���� ���ԵǾ� �ֽ��ϴ�.(".__LINE__.")   '); history.back(); </script>\n";
            exit;
        }
    }

}


#--------------------------------------------------------------------------------------------------------
# END : ���� ����
#--------------------------------------------------------------------------------------------------------


?>