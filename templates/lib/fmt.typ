#let t(strings, key, ..named) = {
  let result = strings.at(key)
  for (name, value) in named.named() {
    result = result.replace("{" + name + "}", str(value))
  }
  result
}
#let num(n) = {
  let digits = str(n)
  let result = ""
  for (i, digit) in digits.clusters().enumerate() {
    if i > 0 and calc.rem(digits.len() - i, 3) == 0 and digit != "-" and digits.at(i - 1) != "-" {
      result += ","
    }
    result += digit
  }
  result
}
