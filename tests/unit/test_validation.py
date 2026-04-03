"""
Unit tests for validation.py module.

Tests all 16 validation functions with valid inputs, invalid inputs,
and edge cases.
"""

import pytest
from validation import (
    ValidationError,
    validate_username,
    validate_password,
    validate_email,
    validate_phone,
    validate_zipcode,
    validate_driving_license,
    validate_date,
    validate_name,
    validate_house_number,
    validate_city,
    validate_gender,
    validate_serial_number,
    validate_scooter_type,
    validate_state_of_charge,
    VALID_CITIES,
)


# ============================================================================
# Username Validation Tests
# ============================================================================


@pytest.mark.unit
class TestUsernameValidation:
    """Test validate_username function"""

    def test_valid_usernames(self):
        """Test valid username inputs"""
        assert validate_username("john_doe") == "john_doe"
        assert validate_username("JANE.DOE") == "jane.doe"
        assert validate_username("user_123") == "user_123"
        assert validate_username("admin_usr") == "admin_usr"

    def test_super_admin_allowed(self):
        """Test that super_admin bypasses length rules"""
        assert validate_username("super_admin") == "super_admin"

    def test_username_case_insensitive(self):
        """Test that usernames are converted to lowercase"""
        assert validate_username("TestUser") == "testuser"
        assert validate_username("UPPERCASE") == "uppercase"

    def test_username_too_short(self):
        """Test usernames that are too short"""
        with pytest.raises(ValidationError, match="at least 8 characters"):
            validate_username("short")

    def test_username_too_long(self):
        """Test usernames that are too long"""
        with pytest.raises(ValidationError, match="at most 10 characters"):
            validate_username("toolongusername")

    def test_username_invalid_start(self):
        """Test usernames that don't start with letter or underscore"""
        with pytest.raises(
            ValidationError, match="must start with a letter or underscore"
        ):
            validate_username("123start")

    def test_username_invalid_chars(self):
        """Test usernames with invalid characters"""
        with pytest.raises(ValidationError, match="can only contain"):
            validate_username("user@name")

    def test_username_non_string(self):
        """Test non-string username"""
        with pytest.raises(ValidationError, match="Username must be a string"):
            validate_username(12345)


# ============================================================================
# Password Validation Tests
# ============================================================================


@pytest.mark.unit
class TestPasswordValidation:
    """Test validate_password function"""

    def test_valid_passwords(self):
        """Test valid password inputs"""
        assert validate_password("MyPassword123!") == "MyPassword123!"
        assert validate_password("Secure@Pass2024") == "Secure@Pass2024"
        assert validate_password("ValidPass123#") == "ValidPass123#"

    def test_password_too_short(self):
        """Test passwords that are too short"""
        with pytest.raises(ValidationError, match="at least 12 characters"):
            validate_password("Short1!")

    def test_password_too_long(self):
        """Test passwords that are too long"""
        with pytest.raises(ValidationError, match="at most 30 characters"):
            validate_password("ThisIsAVeryLongPasswordThatExceeds30Characters!")

    def test_password_no_lowercase(self):
        """Test passwords without lowercase letters"""
        with pytest.raises(ValidationError, match="at least 1 lowercase letter"):
            validate_password("ALLUPPERCASE123!")

    def test_password_no_uppercase(self):
        """Test passwords without uppercase letters"""
        with pytest.raises(ValidationError, match="at least 1 uppercase letter"):
            validate_password("alllowercase123!")

    def test_password_no_digit(self):
        """Test passwords without digits"""
        with pytest.raises(ValidationError, match="at least 1 digit"):
            validate_password("NoDigitsHere!")

    def test_password_no_special_char(self):
        """Test passwords without special characters"""
        with pytest.raises(ValidationError, match="at least 1 special character"):
            validate_password("NoSpecial123")

    def test_password_non_string(self):
        """Test non-string password"""
        with pytest.raises(ValidationError, match="Password must be a string"):
            validate_password(12345678)


# ============================================================================
# Email Validation Tests
# ============================================================================


@pytest.mark.unit
class TestEmailValidation:
    """Test validate_email function"""

    @pytest.mark.parametrize(
        "email,expected",
        [
            ("user@example.com", "user@example.com"),
            ("UPPER@CASE.COM", "upper@case.com"),
            ("test.email+tag@domain.co.uk", "test.email+tag@domain.co.uk"),
            ("  spaces@example.com  ", "spaces@example.com"),
        ],
    )
    def test_valid_emails(self, email, expected):
        """Test valid email inputs"""
        assert validate_email(email) == expected

    def test_email_too_long(self):
        """Test email that exceeds 50 characters"""
        long_email = "a" * 40 + "@example.com"
        with pytest.raises(
            ValidationError, match="cannot be longer than 50 characters"
        ):
            validate_email(long_email)

    @pytest.mark.parametrize(
        "invalid_email",
        [
            "invalid",
            "@example.com",
            "user@",
            "user@.com",
            "user.example.com",
        ],
    )
    def test_invalid_email_format(self, invalid_email):
        """Test invalid email formats"""
        with pytest.raises(ValidationError, match="Invalid email format"):
            validate_email(invalid_email)

    def test_email_non_string(self):
        """Test non-string email"""
        with pytest.raises(ValidationError, match="Email must be a string"):
            validate_email(12345)


# ============================================================================
# Phone Validation Tests
# ============================================================================


@pytest.mark.unit
class TestPhoneValidation:
    """Test validate_phone function"""

    @pytest.mark.parametrize(
        "phone,expected",
        [
            ("12345678", "+31-6-12345678"),
            ("87654321", "+31-6-87654321"),
            ("+31-6-12345678", "+31-6-12345678"),
            ("  12345678  ", "+31-6-12345678"),
        ],
    )
    def test_valid_phones(self, phone, expected):
        """Test valid phone number inputs"""
        assert validate_phone(phone) == expected

    @pytest.mark.parametrize(
        "invalid_phone",
        [
            "1234567",  # Too short
            "123456789",  # Too long
            "1234abcd",  # Contains letters
        ],
    )
    def test_invalid_phones(self, invalid_phone):
        """Test invalid phone number formats"""
        with pytest.raises(ValidationError, match="must be exactly 8 digits"):
            validate_phone(invalid_phone)

    def test_phone_non_string(self):
        """Test non-string phone number"""
        with pytest.raises(ValidationError, match="Phone number must be a string"):
            validate_phone(12345678)


# ============================================================================
# Zipcode Validation Tests
# ============================================================================


@pytest.mark.unit
class TestZipcodeValidation:
    """Test validate_zipcode function"""

    @pytest.mark.parametrize(
        "zipcode,expected",
        [
            ("3011AB", "3011AB"),
            ("1234XY", "1234XY"),
            ("3011ab", "3011AB"),  # Converts to uppercase
            ("3011 AB", "3011AB"),  # Removes spaces
        ],
    )
    def test_valid_zipcodes(self, zipcode, expected):
        """Test valid zipcode inputs"""
        assert validate_zipcode(zipcode) == expected

    @pytest.mark.parametrize(
        "invalid_zipcode",
        [
            "301AB",  # Too short
            "3011ABC",  # Too long
            "ABCD12",  # Wrong format
            "3011A",  # Incomplete
        ],
    )
    def test_invalid_zipcodes(self, invalid_zipcode):
        """Test invalid zipcode formats"""
        with pytest.raises(ValidationError, match="Invalid zipcode format"):
            validate_zipcode(invalid_zipcode)

    def test_zipcode_non_string(self):
        """Test non-string zipcode"""
        with pytest.raises(ValidationError, match="Zipcode must be a string"):
            validate_zipcode(3011)


# ============================================================================
# Driving License Validation Tests
# ============================================================================


@pytest.mark.unit
class TestDrivingLicenseValidation:
    """Test validate_driving_license function"""

    @pytest.mark.parametrize(
        "license,expected",
        [
            ("AB1234567", "AB1234567"),
            ("X1234567", "X1234567"),
            ("ab1234567", "AB1234567"),  # Converts to uppercase
            ("AB 1234567", "AB1234567"),  # Removes spaces
        ],
    )
    def test_valid_licenses(self, license, expected):
        """Test valid driving license inputs"""
        assert validate_driving_license(license) == expected

    @pytest.mark.parametrize(
        "invalid_license",
        [
            "ABC123456",  # Too many letters
            "A123456",  # Too few digits
            "1234567",  # No letters
            "ABCDEFG",  # No digits
        ],
    )
    def test_invalid_licenses(self, invalid_license):
        """Test invalid driving license formats"""
        with pytest.raises(ValidationError, match="Invalid driving license format"):
            validate_driving_license(invalid_license)

    def test_driving_license_non_string(self):
        """Test non-string driving license"""
        with pytest.raises(ValidationError, match="Driving license must be a string"):
            validate_driving_license(12345678)


# ============================================================================
# Date Validation Tests
# ============================================================================


@pytest.mark.unit
class TestDateValidation:
    """Test validate_date function (ISO YYYY-MM-DD format)"""

    @pytest.mark.parametrize(
        "date_str",
        [
            "1995-03-15",
            "2000-01-01",
            "2024-12-31",
            "2020-02-29",  # Leap year
        ],
    )
    def test_valid_dates(self, date_str):
        """Test valid date inputs in YYYY-MM-DD format"""
        assert validate_date(date_str) == date_str

    @pytest.mark.parametrize(
        "invalid_date",
        [
            "15/03/1995",  # Wrong separator
            "15-03-2024",  # Wrong format (DD-MM-YYYY instead of YYYY-MM-DD)
            "2024-01-32",  # Invalid day
            "2024-13-15",  # Invalid month
            "2023-02-29",  # Not a leap year
        ],
    )
    def test_invalid_dates(self, invalid_date):
        """Test invalid date inputs"""
        with pytest.raises(ValidationError):
            validate_date(invalid_date)

    def test_date_non_string(self):
        """Test non-string date"""
        with pytest.raises(ValidationError, match="Date must be a string"):
            validate_date(20241231)


# ============================================================================
# Name Validation Tests
# ============================================================================


@pytest.mark.unit
class TestNameValidation:
    """Test validate_name function"""

    @pytest.mark.parametrize(
        "name",
        [
            "John",
            "Mary-Jane",
            "O'Brien",
            "Van der Berg",
        ],
    )
    def test_valid_names(self, name):
        """Test valid name inputs"""
        assert validate_name(name) == name

    def test_name_too_long(self):
        """Test name that exceeds 50 characters"""
        long_name = "A" * 51
        with pytest.raises(
            ValidationError, match="cannot be longer than 50 characters"
        ):
            validate_name(long_name)

    def test_name_empty(self):
        """Test empty name"""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_name("")

    def test_name_invalid_chars(self):
        """Test name with invalid characters"""
        with pytest.raises(ValidationError, match="can only contain"):
            validate_name("John123")

    def test_name_non_string(self):
        """Test non-string name"""
        with pytest.raises(ValidationError, match="Name must be a string"):
            validate_name(12345)


# ============================================================================
# House Number Validation Tests
# ============================================================================


@pytest.mark.unit
class TestHouseNumberValidation:
    """Test validate_house_number function"""

    @pytest.mark.parametrize(
        "house_number",
        [
            "42",
            "42A",
            "42-1",
            "123bis",
        ],
    )
    def test_valid_house_numbers(self, house_number):
        """Test valid house number inputs"""
        assert validate_house_number(house_number) == house_number

    def test_house_number_too_long(self):
        """Test house number that exceeds 6 characters"""
        with pytest.raises(ValidationError, match="cannot be longer than 6 characters"):
            validate_house_number("1234567")

    def test_house_number_empty(self):
        """Test empty house number"""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_house_number("")

    def test_house_number_invalid_start(self):
        """Test house number that doesn't start with digit"""
        with pytest.raises(ValidationError, match="must start with a digit"):
            validate_house_number("A42")

    def test_house_number_invalid_chars(self):
        """Test house number with invalid special characters"""
        with pytest.raises(ValidationError, match="contains invalid characters"):
            validate_house_number("42@A")

    def test_house_number_non_string(self):
        """Test non-string house number"""
        with pytest.raises(ValidationError, match="House number must be a string"):
            validate_house_number(42)


# ============================================================================
# City Validation Tests
# ============================================================================


@pytest.mark.unit
class TestCityValidation:
    """Test validate_city function"""

    @pytest.mark.parametrize("city", VALID_CITIES)
    def test_valid_cities(self, city):
        """Test all valid cities"""
        assert validate_city(city) == city

    def test_invalid_city(self):
        """Test invalid city"""
        with pytest.raises(ValidationError, match="must be one of"):
            validate_city("InvalidCity")

    def test_city_non_string(self):
        """Test non-string city"""
        with pytest.raises(ValidationError, match="City must be a string"):
            validate_city(12345)


# ============================================================================
# Gender Validation Tests
# ============================================================================


@pytest.mark.unit
class TestGenderValidation:
    """Test validate_gender function"""

    @pytest.mark.parametrize("gender", ["Male", "Female"])
    def test_valid_genders(self, gender):
        """Test valid gender inputs"""
        assert validate_gender(gender) == gender

    def test_invalid_gender(self):
        """Test invalid gender"""
        with pytest.raises(ValidationError, match="must be 'Male' or 'Female'"):
            validate_gender("Other")

    def test_gender_non_string(self):
        """Test non-string gender"""
        with pytest.raises(ValidationError, match="Gender must be a string"):
            validate_gender(123)


# ============================================================================
# Serial Number Validation Tests
# ============================================================================


@pytest.mark.unit
class TestSerialNumberValidation:
    """Test validate_serial_number function"""

    @pytest.mark.parametrize(
        "serial,expected",
        [
            ("ABC1234567", "ABC1234567"),
            ("abc123xyz0", "ABC123XYZ0"),  # Converts to uppercase
            ("  SERIAL2024FLEET  ", "SERIAL2024FLEET"),  # Strips whitespace
        ],
    )
    def test_valid_serial_numbers(self, serial, expected):
        """Test valid serial number inputs"""
        assert validate_serial_number(serial) == expected

    def test_serial_too_short(self):
        """Test serial number that is too short"""
        with pytest.raises(ValidationError, match="at least 10 characters"):
            validate_serial_number("ABC12")

    def test_serial_too_long(self):
        """Test serial number that is too long"""
        with pytest.raises(ValidationError, match="at most 17 characters"):
            validate_serial_number("A" * 18)

    def test_serial_invalid_chars(self):
        """Test serial number with invalid characters"""
        with pytest.raises(
            ValidationError, match="can only contain letters and digits"
        ):
            validate_serial_number("ABC-123DEFGH")

    def test_serial_number_non_string(self):
        """Test non-string serial number"""
        with pytest.raises(ValidationError, match="Serial number must be a string"):
            validate_serial_number(123456)


# ============================================================================
# Scooter Type Validation Tests
# ============================================================================


@pytest.mark.unit
class TestScooterTypeValidation:
    """Test validate_scooter_type function"""

    @pytest.mark.parametrize(
        "scooter_type",
        [
            "E-Scooter",
            "Model X",
            "Pro 2024",
        ],
    )
    def test_valid_scooter_types(self, scooter_type):
        """Test valid scooter type inputs"""
        assert validate_scooter_type(scooter_type) == scooter_type

    def test_scooter_type_too_short(self):
        """Test scooter type that is too short"""
        with pytest.raises(ValidationError, match="at least 2 characters"):
            validate_scooter_type("A")

    def test_scooter_type_too_long(self):
        """Test scooter type that is too long"""
        with pytest.raises(ValidationError, match="at most 30 characters"):
            validate_scooter_type("A" * 31)

    def test_scooter_type_invalid_chars(self):
        """Test scooter type with invalid characters"""
        with pytest.raises(ValidationError, match="can only contain"):
            validate_scooter_type("E-Scooter@#$")

    def test_scooter_type_non_string(self):
        """Test non-string scooter type"""
        with pytest.raises(ValidationError, match="Scooter type must be a string"):
            validate_scooter_type(12345)


# ============================================================================
# State of Charge Validation Tests
# ============================================================================


@pytest.mark.unit
class TestStateOfChargeValidation:
    """Test validate_state_of_charge function"""

    @pytest.mark.parametrize(
        "level,expected",
        [
            (0, 0),
            (50, 50),
            (100, 100),
            ("75", 75),  # String input
            ("  100  ", 100),  # String with spaces
        ],
    )
    def test_valid_state_of_charge(self, level, expected):
        """Test valid state of charge inputs"""
        assert validate_state_of_charge(level) == expected

    def test_state_of_charge_negative(self):
        """Test negative state of charge"""
        with pytest.raises(ValidationError, match="cannot be negative"):
            validate_state_of_charge(-1)

    def test_state_of_charge_too_high(self):
        """Test state of charge above 100"""
        with pytest.raises(ValidationError, match="cannot exceed 100"):
            validate_state_of_charge(101)

    def test_state_of_charge_invalid_string(self):
        """Test non-numeric string"""
        with pytest.raises(ValidationError, match="must be a number"):
            validate_state_of_charge("abc")

    def test_state_of_charge_non_integer(self):
        """Test non-integer state of charge (like float)"""
        with pytest.raises(ValidationError, match="must be an integer"):
            validate_state_of_charge(50.5)


# ============================================================================
# Birthday Validation Tests
# ============================================================================


@pytest.mark.unit
class TestBirthdayValidation:
    """Test validate_birthday function"""

    def test_valid_birthdays(self):
        """Test valid birthday inputs"""
        from validation import validate_birthday

        assert validate_birthday("15-03-1995") == "15-03-1995"
        assert validate_birthday("01-01-2000") == "01-01-2000"
        assert validate_birthday("29-02-2000") == "29-02-2000"  # Leap year

    def test_birthday_non_string(self):
        """Test non-string birthday"""
        from validation import validate_birthday

        with pytest.raises(ValidationError, match="Birthday must be a string"):
            validate_birthday(20001231)

    def test_birthday_invalid_format(self):
        """Test invalid birthday format"""
        from validation import validate_birthday

        with pytest.raises(ValidationError, match="Invalid birthday format"):
            validate_birthday("1995-03-15")  # Wrong format
        with pytest.raises(ValidationError, match="Invalid birthday format"):
            validate_birthday("15/03/1995")  # Wrong separator

    def test_birthday_invalid_date(self):
        """Test invalid calendar date"""
        from validation import validate_birthday

        with pytest.raises(ValidationError, match="valid calendar date"):
            validate_birthday("30-02-2000")  # Feb 30 doesn't exist
        with pytest.raises(ValidationError, match="valid calendar date"):
            validate_birthday("31-04-2000")  # April has 30 days

    def test_birthday_future_date(self):
        """Test future birthday"""
        from validation import validate_birthday
        from datetime import datetime, timedelta

        future_date = datetime.now() + timedelta(days=365)
        future_str = future_date.strftime("%d-%m-%Y")

        with pytest.raises(ValidationError, match="cannot be in the future"):
            validate_birthday(future_str)

    def test_birthday_too_old(self):
        """Test birthday more than 150 years ago"""
        from validation import validate_birthday

        with pytest.raises(ValidationError, match="150 years in the past"):
            validate_birthday("01-01-1800")


# ============================================================================
# GPS Location Validation Tests
# ============================================================================


@pytest.mark.unit
class TestGPSLocationValidation:
    """Test validate_gps_location function"""

    def test_valid_gps_locations(self):
        """Test valid GPS coordinates"""
        from validation import validate_gps_location

        # Rotterdam Centraal
        lat, lon = validate_gps_location(51.92481, 4.46910)
        assert lat == 51.92481
        assert lon == 4.46910

        # Test string inputs
        lat, lon = validate_gps_location("51.92481", "4.46910")
        assert lat == 51.92481
        assert lon == 4.46910

        # Test edge cases
        lat, lon = validate_gps_location(51.8000, 4.2500)
        assert lat == 51.8
        assert lon == 4.25

    def test_gps_invalid_latitude(self):
        """Test invalid latitude"""
        from validation import validate_gps_location

        with pytest.raises(ValidationError, match="Latitude must be within Rotterdam"):
            validate_gps_location(51.7, 4.5)  # Too south
        with pytest.raises(ValidationError, match="Latitude must be within Rotterdam"):
            validate_gps_location(52.1, 4.5)  # Too north

    def test_gps_invalid_longitude(self):
        """Test invalid longitude"""
        from validation import validate_gps_location

        with pytest.raises(ValidationError, match="Longitude must be within Rotterdam"):
            validate_gps_location(51.9, 4.2)  # Too west
        with pytest.raises(ValidationError, match="Longitude must be within Rotterdam"):
            validate_gps_location(51.9, 4.7)  # Too east

    def test_gps_invalid_types(self):
        """Test invalid coordinate types"""
        from validation import validate_gps_location

        with pytest.raises(ValidationError, match="must be valid numbers"):
            validate_gps_location("invalid", "4.5")
        with pytest.raises(ValidationError, match="must be numbers"):
            validate_gps_location(None, 4.5)


# ============================================================================
# Brand Validation Tests
# ============================================================================


@pytest.mark.unit
class TestBrandValidation:
    """Test validate_brand function"""

    def test_valid_brands(self):
        """Test valid brand inputs"""
        from validation import validate_brand

        assert validate_brand("Segway") == "Segway"
        assert validate_brand("NIU") == "NIU"
        assert validate_brand("E-Rider") == "E-Rider"

    def test_brand_non_string(self):
        """Test non-string brand"""
        from validation import validate_brand

        with pytest.raises(ValidationError, match="Brand must be a string"):
            validate_brand(12345)

    def test_brand_too_short(self):
        """Test brand too short"""
        from validation import validate_brand

        with pytest.raises(ValidationError, match="at least 2 characters"):
            validate_brand("A")

    def test_brand_too_long(self):
        """Test brand too long"""
        from validation import validate_brand

        with pytest.raises(ValidationError, match="at most 50 characters"):
            validate_brand("A" * 51)

    def test_brand_invalid_chars(self):
        """Test brand with invalid characters"""
        from validation import validate_brand

        with pytest.raises(ValidationError, match="can only contain"):
            validate_brand("Brand@123")


# ============================================================================
# Model Validation Tests
# ============================================================================


@pytest.mark.unit
class TestModelValidation:
    """Test validate_model function"""

    def test_valid_models(self):
        """Test valid model inputs"""
        from validation import validate_model

        assert validate_model("ES2") == "ES2"
        assert validate_model("Pro Max") == "Pro Max"
        assert validate_model("X-100") == "X-100"

    def test_model_non_string(self):
        """Test non-string model"""
        from validation import validate_model

        with pytest.raises(ValidationError, match="Model must be a string"):
            validate_model(12345)

    def test_model_too_short(self):
        """Test model too short"""
        from validation import validate_model

        with pytest.raises(ValidationError, match="at least 2 characters"):
            validate_model("A")

    def test_model_too_long(self):
        """Test model too long"""
        from validation import validate_model

        with pytest.raises(ValidationError, match="at most 50 characters"):
            validate_model("A" * 51)

    def test_model_invalid_chars(self):
        """Test model with invalid characters"""
        from validation import validate_model

        with pytest.raises(ValidationError, match="can only contain"):
            validate_model("Model@#$")


# ============================================================================
# Top Speed Validation Tests
# ============================================================================


@pytest.mark.unit
class TestTopSpeedValidation:
    """Test validate_top_speed function"""

    def test_valid_top_speeds(self):
        """Test valid top speed inputs"""
        from validation import validate_top_speed

        assert validate_top_speed(25) == 25.0
        assert validate_top_speed(45.5) == 45.5
        assert validate_top_speed("30") == 30.0
        assert validate_top_speed("45.5") == 45.5

    def test_top_speed_negative(self):
        """Test negative top speed"""
        from validation import validate_top_speed

        with pytest.raises(ValidationError, match="cannot be negative"):
            validate_top_speed(-10)

    def test_top_speed_too_high(self):
        """Test top speed too high"""
        from validation import validate_top_speed

        with pytest.raises(ValidationError, match="cannot exceed 80"):
            validate_top_speed(100)

    def test_top_speed_invalid_string(self):
        """Test invalid string top speed"""
        from validation import validate_top_speed

        with pytest.raises(ValidationError, match="must be a number"):
            validate_top_speed("fast")

    def test_top_speed_invalid_type(self):
        """Test invalid type top speed"""
        from validation import validate_top_speed

        with pytest.raises(ValidationError, match="must be a number"):
            validate_top_speed(None)


# ============================================================================
# Battery Capacity Validation Tests
# ============================================================================


@pytest.mark.unit
class TestBatteryCapacityValidation:
    """Test validate_battery_capacity function"""

    def test_valid_battery_capacities(self):
        """Test valid battery capacity inputs"""
        from validation import validate_battery_capacity

        assert validate_battery_capacity(500) == 500
        assert validate_battery_capacity(750) == 750
        assert validate_battery_capacity("1000") == 1000

    def test_battery_capacity_negative(self):
        """Test negative battery capacity"""
        from validation import validate_battery_capacity

        with pytest.raises(ValidationError, match="cannot be negative"):
            validate_battery_capacity(-100)

    def test_battery_capacity_too_high(self):
        """Test battery capacity too high"""
        from validation import validate_battery_capacity

        with pytest.raises(ValidationError, match="cannot exceed 10000"):
            validate_battery_capacity(15000)

    def test_battery_capacity_invalid_string(self):
        """Test invalid string battery capacity"""
        from validation import validate_battery_capacity

        with pytest.raises(ValidationError, match="must be a number"):
            validate_battery_capacity("large")

    def test_battery_capacity_invalid_type(self):
        """Test invalid type battery capacity"""
        from validation import validate_battery_capacity

        with pytest.raises(ValidationError, match="must be an integer"):
            validate_battery_capacity(500.5)


# ============================================================================
# Target Range SoC Validation Tests
# ============================================================================


@pytest.mark.unit
class TestTargetRangeSOCValidation:
    """Test validate_target_range_soc function"""

    def test_valid_target_range_soc(self):
        """Test valid target range SoC"""
        from validation import validate_target_range_soc

        min_soc, max_soc = validate_target_range_soc(20, 80)
        assert min_soc == 20
        assert max_soc == 80

        # Test string inputs
        min_soc, max_soc = validate_target_range_soc("20", "80")
        assert min_soc == 20
        assert max_soc == 80

    def test_target_range_min_greater_than_max(self):
        """Test min SoC greater than or equal to max SoC"""
        from validation import validate_target_range_soc

        with pytest.raises(ValidationError, match="must be less than"):
            validate_target_range_soc(80, 20)
        with pytest.raises(ValidationError, match="must be less than"):
            validate_target_range_soc(50, 50)

    def test_target_range_invalid_min(self):
        """Test invalid min SoC"""
        from validation import validate_target_range_soc

        with pytest.raises(ValidationError, match="Minimum SoC"):
            validate_target_range_soc(-10, 80)
        with pytest.raises(ValidationError, match="Minimum SoC"):
            validate_target_range_soc(110, 120)
        with pytest.raises(ValidationError, match="must be a number"):
            validate_target_range_soc("abc", 80)
        with pytest.raises(ValidationError, match="must be an integer"):
            validate_target_range_soc(20.5, 80)

    def test_target_range_invalid_max(self):
        """Test invalid max SoC"""
        from validation import validate_target_range_soc

        with pytest.raises(ValidationError, match="Maximum SoC"):
            validate_target_range_soc(20, -10)
        with pytest.raises(ValidationError, match="Maximum SoC"):
            validate_target_range_soc(20, 110)
        with pytest.raises(ValidationError, match="must be a number"):
            validate_target_range_soc(20, "xyz")
        with pytest.raises(ValidationError, match="must be an integer"):
            validate_target_range_soc(20, 80.5)


# ============================================================================
# Out of Service Status Validation Tests
# ============================================================================


@pytest.mark.unit
class TestOutOfServiceStatusValidation:
    """Test validate_out_of_service_status function"""

    def test_valid_out_of_service_statuses(self):
        """Test valid out of service status inputs"""
        from validation import validate_out_of_service_status

        assert validate_out_of_service_status(True) is True
        assert validate_out_of_service_status(False) is False
        assert validate_out_of_service_status("Yes") is True
        assert validate_out_of_service_status("yes") is True
        assert validate_out_of_service_status("No") is False
        assert validate_out_of_service_status("no") is False
        assert validate_out_of_service_status("True") is True
        assert validate_out_of_service_status("true") is True
        assert validate_out_of_service_status("False") is False
        assert validate_out_of_service_status("false") is False
        assert validate_out_of_service_status("1") is True
        assert validate_out_of_service_status("0") is False
        assert validate_out_of_service_status(1) is True
        assert validate_out_of_service_status(0) is False

    def test_out_of_service_invalid_string(self):
        """Test invalid string status"""
        from validation import validate_out_of_service_status

        with pytest.raises(ValidationError, match="Invalid out-of-service status"):
            validate_out_of_service_status("maybe")

    def test_out_of_service_invalid_int(self):
        """Test invalid integer status"""
        from validation import validate_out_of_service_status

        with pytest.raises(ValidationError, match="Invalid out-of-service status"):
            validate_out_of_service_status(2)

    def test_out_of_service_invalid_type(self):
        """Test invalid type status"""
        from validation import validate_out_of_service_status

        with pytest.raises(
            ValidationError, match="must be boolean, string, or integer"
        ):
            validate_out_of_service_status(None)


# ============================================================================
# Mileage Validation Tests
# ============================================================================


@pytest.mark.unit
class TestMileageValidation:
    """Test validate_mileage function"""

    def test_valid_mileages(self):
        """Test valid mileage inputs"""
        from validation import validate_mileage

        assert validate_mileage(0) == 0.0
        assert validate_mileage(1500) == 1500.0
        assert validate_mileage(2500.5) == 2500.5
        assert validate_mileage("3000") == 3000.0
        assert validate_mileage("4500.5") == 4500.5

    def test_mileage_negative(self):
        """Test negative mileage"""
        from validation import validate_mileage

        with pytest.raises(ValidationError, match="cannot be negative"):
            validate_mileage(-100)

    def test_mileage_too_high(self):
        """Test mileage too high"""
        from validation import validate_mileage

        with pytest.raises(ValidationError, match="cannot exceed 999999"):
            validate_mileage(1000000)

    def test_mileage_invalid_string(self):
        """Test invalid string mileage"""
        from validation import validate_mileage

        with pytest.raises(ValidationError, match="must be a number"):
            validate_mileage("many")

    def test_mileage_invalid_type(self):
        """Test invalid type mileage"""
        from validation import validate_mileage

        with pytest.raises(ValidationError, match="must be a number"):
            validate_mileage(None)


# ============================================================================
# Null Byte Detection Tests
# ============================================================================


@pytest.mark.unit
class TestNullByteDetection:
    """Test null byte detection across all validation functions"""

    def test_null_byte_in_username(self):
        """Test null byte detection in username"""
        with pytest.raises(ValidationError, match="null-byte"):
            validate_username("user\0name")

    def test_null_byte_in_password(self):
        """Test null byte detection in password"""
        from validation import validate_password

        with pytest.raises(ValidationError, match="null-byte"):
            validate_password("Pass\0word123!")

    def test_null_byte_in_email(self):
        """Test null byte detection in email"""
        from validation import validate_email

        with pytest.raises(ValidationError, match="null-byte"):
            validate_email("user\0@example.com")

    def test_null_byte_in_phone(self):
        """Test null byte detection in phone"""
        from validation import validate_phone

        with pytest.raises(ValidationError):
            validate_phone("123\x00456")

    def test_null_byte_in_zipcode(self):
        """Test null byte detection in zipcode"""
        from validation import validate_zipcode

        with pytest.raises(ValidationError, match="null-byte"):
            validate_zipcode("3011\0AB")

    def test_null_byte_in_name(self):
        """Test null byte detection in name"""
        from validation import validate_name

        with pytest.raises(ValidationError, match="null-byte"):
            validate_name("John\0Doe")

    def test_null_byte_in_city(self):
        """Test null byte detection in city"""
        from validation import validate_city

        with pytest.raises(ValidationError, match="null-byte"):
            validate_city("Amster\0dam")

    def test_null_byte_in_serial_number(self):
        """Test null byte detection in serial number"""
        from validation import validate_serial_number

        with pytest.raises(ValidationError, match="null-byte"):
            validate_serial_number("ABCDEFGH\x00IJ")

    def test_null_byte_in_gps(self):
        """Test null byte detection in GPS coordinates"""
        from validation import validate_gps_location

        with pytest.raises(ValidationError):
            validate_gps_location("51.92\x0048", "4.469")
        with pytest.raises(ValidationError):
            validate_gps_location("51.9248", "4.4\x0069")
