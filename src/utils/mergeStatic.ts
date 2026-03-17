export function mergeStatic<A extends object, B extends object>(a: A, b: B): A & B {
  const result = Object.create(null);
  const skip = new Set(["prototype", "length", "name"]);

  function copyFrom(src: any, bindTarget: any) {
    let current = src;
    while (current && current !== Function.prototype) {
      for (const key of Object.getOwnPropertyNames(current)) {
        if (skip.has(key) || key in result) continue; // A a priorité sur B
        const desc = Object.getOwnPropertyDescriptor(current, key)!;
        if (typeof desc.value === "function") {
          desc.value = desc.value.bind(bindTarget);
        }
        Object.defineProperty(result, key, desc);
      }
      current = Object.getPrototypeOf(current);
    }
  }

  copyFrom(b, b); // B en premier
  copyFrom(a, a); // A écrase B en cas de conflit

  return result as A & B;
}