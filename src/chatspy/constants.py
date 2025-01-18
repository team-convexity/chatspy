import pycountry

SDG_GOALS = [
    (1, "No Poverty"),
    (2, "Zero Hunger"),
    (3, "Good Health and Well-being"),
    (5, "Gender Equality"),
    (4, "Quality Education"),
    (10, "Reduced Inequality"),
    (6, "Clean Water and Sanitation"),
    (7, "Affordable and Clean Energy"),
    (8, "Decent Work and Economic Growth"),
    (9, "Industry, Innovation, and Infrastructure"),
    (11, "Sustainable Cities and Communities"),
    (12, "Responsible Consumption and Production"),
    (13, "Climate Action"),
    (14, "Life Below Water"),
    (15, "Life on Land"),
    (16, "Peace, Justice, and Strong Institutions"),
    (17, "Partnerships for the Goals"),
]

CURRENCY_CHOICES = [
    ("USD", "United States Dollar"),
    ("EUR", "Euro"),
    ("JPY", "Japanese Yen"),
    ("GBP", "British Pound Sterling"),
    ("AUD", "Australian Dollar"),
    ("CAD", "Canadian Dollar"),
    ("CHF", "Swiss Franc"),
    ("CNY", "Chinese Yuan"),
    ("SEK", "Swedish Krona"),
    ("NZD", "New Zealand Dollar"),
    ("MXN", "Mexican Peso"),
    ("SGD", "Singapore Dollar"),
    ("HKD", "Hong Kong Dollar"),
    ("NOK", "Norwegian Krone"),
    ("KRW", "South Korean Won"),
    ("TRY", "Turkish Lira"),
    ("INR", "Indian Rupee"),
    ("RUB", "Russian Ruble"),
    ("BRL", "Brazilian Real"),
    ("ZAR", "South African Rand"),
    ("NGN", "Nigerian Naira"),
]

COUNTRY_CHOICES = [(country.alpha_2, country.name) for country in pycountry.countries]

STATE_CHOICES = {}

for country in pycountry.countries:
    subdivisions = pycountry.subdivisions.get(country_code=country.alpha_2)
    if subdivisions:
        STATE_CHOICES[country.alpha_2] = [(subdivision.code, subdivision.name) for subdivision in subdivisions]


def get_country_states(country_code):
    """
    Returns a list of all states/regions in a country.

    Args:
        country_code (str): The two-letter country code.

    Returns:
        list: A list of tuples containing state codes and names for the country.
    """
    return STATE_CHOICES.get(country_code, [])
