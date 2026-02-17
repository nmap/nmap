diff --git a/esm/index.js b/esm/index.js
index c83bc63a2c10431fb62e25b7d490656a3796f301..bcae513cc20a4be6c38dc116e0b8d9bacda62b5b 100644
--- a/esm/index.js
+++ b/esm/index.js
@@ -338,6 +338,23 @@ const Switch = ({ children, location }) => {
   const router = useRouter();
   const [originalLocation] = useLocationFromRouter(router);
 
+  // Collect all route paths to window object
+  if (typeof window !== 'undefined') {
+    if (!window.__WOUTER_ROUTES__) {
+      window.__WOUTER_ROUTES__ = [];
+    }
+
+    const allChildren = flattenChildren(children);
+    allChildren.forEach((element) => {
+      if (isValidElement(element) && element.props.path) {
+        const path = element.props.path;
+        if (!window.__WOUTER_ROUTES__.includes(path)) {
+          window.__WOUTER_ROUTES__.push(path);
+        }
+      }
+    });
+  }
+
   for (const element of flattenChildren(children)) {
     let match = 0;
 
