#let t(strings, key, ..named) = {
  let result = strings.at(key, default: none)
  if result == none { panic("missing string key: " + key) }
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

#let status-label(strings, key) = {
  let known = ("fixed", "affected", "will_not_fix", "end_of_life", "fix_deferred", "under_investigation")
  if key in known {
    t(strings, "status_" + key)
  } else if key == "unknown" {
    t(strings, "status_other")
  } else {
    t(strings, "status_other") + " (" + key + ")"
  }
}

// Allow identifiers to wrap at punctuation without adding visible hyphens.
#let breakable-id(s) = {
  let result = s
  for separator in ("/", ":", ".", "-", "+", "_", "@") {
    result = result.replace(separator, separator + "\u{200B}")
  }
  result
}
