<?


#--------------------------------------------------------------------------------------------------------
# BEGIN : XSS 차단
#--------------------------------------------------------------------------------------------------------
/*
    @Function
        mixed filter_input_array ( int $type [, mixed $definition [, bool $add_empty = TRUE ]] )
    @Parameters
        $type : INPUT_GET, INPUT_POST, INPUT_COOKIE, INPUT_SERVER, INPUT_ENV.
        $definition :
            필터상수 : http://php.net/manual/en/filter.constants.php
                    FILTER_SANITIZE_ENCODED
                    FILTER_VALIDATE_INT
                    FILTER_REQUIRE_ARRAY
                    FILTER_REQUIRE_SCALAR
    @ReturnValues

*/

$_GET = filter_input_array(INPUT_GET, FILTER_SANITIZE_STRING);
$_POST = filter_input_array(INPUT_POST, FILTER_SANITIZE_STRING);

# 모든 GET 변수에 대해 HTML을 제거한다.
$_GET = array_map('htmlspecialchars', $_GET);


#--------------------------------------------------------------------------------------------------------
# END : XSS 차단
#--------------------------------------------------------------------------------------------------------





#--------------------------------------------------------------------------------------------------------
# BEGIN : SQL INJECTION 방지 : $_POST $_GET 전역에 stripslashes() 해준다.
#--------------------------------------------------------------------------------------------------------
/*
    php.ini의 magic_quotes_gpc = On 인 경우
    GPC 전역변수에 자동으로 슬래시가 붙어온다.
    이를 제거한 후 mysql_real_escape_string() 을 사용한다.
    사용자정의함수(_stripslashes, _mysql_real_escape_string)는 library.php에서 선언되었다.
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
# END : SQL INJECTION 방지 : $_POST, $_GET 전역에 stripslashes() 해준다.
#--------------------------------------------------------------------------------------------------------





#--------------------------------------------------------------------------------------------------------
# BEGIN : SQL INJECTION 방지 : 특수문자를 에러처리한다.
#--------------------------------------------------------------------------------------------------------
/*
    GET 변수에 허용되는 정상 문자열 이외의 특수문자는 모두 에러처리한다.

	영문 알파벳 : a-z, A-Z
	숫자 : 0-9
	한글 : \x80-\xff
	기타 : 하이픈 -, 언더바 _, 퍼센트기호 %, 마침표 . 쉼표 ,
	* 퍼센트기호는 urlencode 되는 문자열(한글,공백 등)에 필요함

    문제제기 : 정규식 패턴이 올바르게 작동하는가?
    항상 문제가 되는 경우는 아래처럼 URL을 파라미터에 포함한 경우이다.
    : /login.php?url=%2Fre%2Frelation%2Frelation_regist.php
    디렉토리 구분자(/)를 인코딩하면 %2F 인데, 퍼센트기호를 차단하면 이 문자도 같이 걸러진다.

*/

$is_run_sqlx = false;

if($is_run_sqlx && $_GET) {
	foreach($_GET as $key=>$val) {
		//$pattern = "/^[a-zA-Z0-9\x80-\xff-_.,#+%]+$/";
		$pattern = "/^[-a-zA-Z0-9\x80-\xff_\s]*$/";

		if( _preg_match($pattern,$key) ) {
		} else {
            header("Content-type: text/html; charset=utf-8");
			echo "<script>alert('URL 요청에 올바르지 않은 값이 포함되어 있습니다.(".__LINE__.")   '); history.back(); </script>\n";
			exit;
		}

		if( _preg_match($pattern,$val) ) {
		} else {
            header("Content-type: text/html; charset=utf-8");
			echo "<script>alert('URL 요청에 올바르지 않은 값이 포함되어 있습니다.(".__LINE__.")   '); history.back(); </script>\n";
			exit;
		}
	}
}

#--------------------------------------------------------------------------------------------------------
# END : SQL INJECTION 방지 : 특수문자를 에러처리한다.
#--------------------------------------------------------------------------------------------------------





#--------------------------------------------------------------------------------------------------------
# BEGIN : 개별 필터
#--------------------------------------------------------------------------------------------------------
/*
    자주 사용하는 GET 변수의 경우 개별필터를 사용한다.
*/

# 게시판 / 리스트 공통 : 페이지 넘버
if($_GET['page']) {
    $val = $_GET['page'];
    $pattern = "/^[0-9]*$/";
    if( _preg_match($pattern,$val) ) {
    } else {
        header("Content-type: text/html; charset=utf-8");
        echo "<script>alert('URL 요청에 올바르지 않은 값이 포함되어 있습니다.(".__LINE__.")   '); history.back(); </script>\n";
        exit;
    }
}

# 게시판
if(_page=="3") {
    # 게시판 분류코드
    if($_GET['ct']) {
        $val = $_GET['ct'];
        $pattern = "/^[A-Z]*$/";
        if( _preg_match($pattern,$val) ) {
        } else {
            header("Content-type: text/html; charset=utf-8");
            echo "<script>alert('URL 요청에 올바르지 않은 값이 포함되어 있습니다.(".__LINE__.")   '); history.back(); </script>\n";
            exit;
        }
    }

    # 게시판 고유번호
    if($_GET['no']) {
        $val = $_GET['no'];
        $pattern = "/^[0-9]*$/";
        if( _preg_match($pattern,$val) ) {
        } else {
            header("Content-type: text/html; charset=utf-8");
            echo "<script>alert('URL 요청에 올바르지 않은 값이 포함되어 있습니다.(".__LINE__.")   '); history.back(); </script>\n";
            exit;
        }
    }
    # 게시판 고유번호
    if($_GET['num']) {
        $val = $_GET['num'];
        $pattern = "/^[0-9]*$/";
        if( _preg_match($pattern,$val) ) {
        } else {
            header("Content-type: text/html; charset=utf-8");
            echo "<script>alert('URL 요청에 올바르지 않은 값이 포함되어 있습니다.(".__LINE__.")   '); history.back(); </script>\n";
            exit;
        }
    }
}


# 인터넷 홍보
if(_page=="5") {

    # 홍보 구분번호
    if($_GET['keykind']) {
        $val = $_GET['keykind'];
        $pattern = "/^[0-9]*$/";
        if( _preg_match($pattern,$val) ) {
        } else {
            header("Content-type: text/html; charset=utf-8");
            echo "<script>alert('URL 요청에 올바르지 않은 값이 포함되어 있습니다.(".__LINE__.")   '); history.back(); </script>\n";
            exit;
        }
    }

    # 홍보 구분번호
    if($_GET['keykind']) {
        $val = $_GET['keykind'];
        $pattern = "/^[0-9]*$/";
        if( _preg_match($pattern,$val) ) {
        } else {
            header("Content-type: text/html; charset=utf-8");
            echo "<script>alert('URL 요청에 올바르지 않은 값이 포함되어 있습니다.(".__LINE__.")   '); history.back(); </script>\n";
            exit;
        }
    }

}


#--------------------------------------------------------------------------------------------------------
# END : 개별 필터
#--------------------------------------------------------------------------------------------------------


?>