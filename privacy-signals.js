(() => {
  const defineGetter = (target, name, getter) => {
    try {
      const current = Object.getOwnPropertyDescriptor(target, name);
      if (!current || current.configurable) {
        Object.defineProperty(target, name, { configurable: true, enumerable: true, get: getter });
      }
    } catch {}
  };

  defineGetter(Navigator.prototype, "globalPrivacyControl", () => true);
  defineGetter(Navigator.prototype, "doNotTrack", () => "1");
  defineGetter(Navigator.prototype, "msDoNotTrack", () => "1");

  try {
    window.dispatchEvent(new CustomEvent("advanced-blocker-privacy-signals", {
      detail: { globalPrivacyControl: true, doNotTrack: "1" }
    }));
  } catch {}
})();
