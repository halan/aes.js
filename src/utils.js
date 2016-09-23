export const compose = (fn, ...rest) => 
  rest.length === 0 ? fn : (...args) => fn(compose(...rest)(...args))

export const isFirst = (arr, item) => arr.indexOf(item) === 0
export const isLast = (arr, item) => arr.indexOf(item) === arr.length-1
