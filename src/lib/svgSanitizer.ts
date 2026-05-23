/**
 * SVG Sanitizer
 * 
 * Sanitizes SVG content from untrusted sources (like Supabase MFA API)
 * to prevent XSS attacks through malicious SVG code.
 * 
 * This is used when rendering QR codes from the MFA enrollment API.
 */

/**
 * Sanitize SVG content by removing potentially dangerous elements and attributes
 * 
 * @param svgString - Raw SVG string from untrusted source
 * @returns Sanitized SVG string safe for rendering
 */
export function sanitizeSVG(svgString: string): string {
  // Create a DOM parser
  const parser = new DOMParser();
  const doc = parser.parseFromString(svgString, 'image/svg+xml');
  
  // Check if parsing failed
  const parserError = doc.querySelector('parsererror');
  if (parserError) {
    throw new Error('Invalid SVG: Failed to parse');
  }
  
  const svgElement = doc.querySelector('svg');
  if (!svgElement) {
    throw new Error('Invalid SVG: No svg element found');
  }
  
  // Allowed elements for QR codes
  const allowedElements = new Set([
    'svg',
    'rect',
    'path',
    'g',
    'defs',
    'style' // QR codes may use styles for coloring
  ]);
  
  // Allowed attributes (whitelist approach)
  const allowedAttributes = new Set([
    'width',
    'height',
    'viewBox',
    'xmlns',
    'version',
    'x',
    'y',
    'd', // path data
    'fill',
    'stroke',
    'stroke-width',
    'class',
    'id',
    'transform'
  ]);
  
  // Dangerous attributes that should never be allowed
  const dangerousAttributes = new Set([
    'onload',
    'onerror',
    'onclick',
    'onmouseover',
    'onmouseout',
    'onfocus',
    'onblur',
    'onchange',
    'onsubmit',
    'onkeydown',
    'onkeyup',
    'onkeypress',
    'onanimationstart',
    'onanimationend',
    'ontransitionend'
  ]);
  
  // Recursively sanitize elements
  function sanitizeElement(element: Element): boolean {
    const tagName = element.tagName.toLowerCase();
    
    // Remove non-allowed elements
    if (!allowedElements.has(tagName)) {
      return false; // Signal to remove this element
    }
    
    // Check for dangerous content in <style> tags
    if (tagName === 'style') {
      const styleContent = element.textContent || '';
      // Block styles that contain javascript: or @import
      if (styleContent.includes('javascript:') || 
          styleContent.includes('@import') ||
          styleContent.includes('expression(')) {
        return false;
      }
    }
    
    // Remove dangerous and non-allowed attributes
    const attributes = Array.from(element.attributes);
    for (const attr of attributes) {
      const attrName = attr.name.toLowerCase();
      
      // Always remove dangerous attributes
      if (dangerousAttributes.has(attrName)) {
        element.removeAttribute(attr.name);
        continue;
      }
      
      // Remove non-allowed attributes
      if (!allowedAttributes.has(attrName)) {
        element.removeAttribute(attr.name);
        continue;
      }
      
      // Check attribute values for javascript: or data: URLs
      const attrValue = attr.value.toLowerCase();
      if (attrValue.includes('javascript:') || 
          attrValue.includes('data:text/html')) {
        element.removeAttribute(attr.name);
      }
    }
    
    // Recursively sanitize children
    const children = Array.from(element.children);
    for (const child of children) {
      if (!sanitizeElement(child)) {
        element.removeChild(child);
      }
    }
    
    return true; // Keep this element
  }
  
  // Sanitize the SVG
  sanitizeElement(svgElement);
  
  // Serialize back to string
  const serializer = new XMLSerializer();
  return serializer.serializeToString(svgElement);
}

/**
 * Validate that an SVG string looks like a QR code
 * QR codes should have specific characteristics
 * 
 * @param svgString - SVG string to validate
 * @returns true if it looks like a QR code
 */
export function validateQRCodeSVG(svgString: string): boolean {
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(svgString, 'image/svg+xml');
    const svgElement = doc.querySelector('svg');
    
    if (!svgElement) return false;
    
    // QR codes should have viewBox or width/height
    const hasViewBox = svgElement.hasAttribute('viewBox');
    const hasWidth = svgElement.hasAttribute('width');
    const hasHeight = svgElement.hasAttribute('height');
    
    if (!hasViewBox && (!hasWidth || !hasHeight)) {
      return false;
    }
    
    // QR codes typically contain rect or path elements
    const hasRects = svgElement.querySelectorAll('rect').length > 0;
    const hasPaths = svgElement.querySelectorAll('path').length > 0;
    
    return hasRects || hasPaths;
  } catch (e) {
    return false;
  }
}

/**
 * Sanitize and validate QR code SVG
 * Combines sanitization and validation in one function
 * 
 * @param svgString - Raw SVG string from untrusted source
 * @returns Sanitized SVG string
 * @throws Error if SVG is invalid or doesn't look like a QR code
 */
export function sanitizeAndValidateQRCode(svgString: string): string {
  if (!svgString || typeof svgString !== 'string') {
    throw new Error('Invalid SVG: Empty or non-string input');
  }
  
  // Validate basic structure
  if (!validateQRCodeSVG(svgString)) {
    throw new Error('Invalid QR code: Does not match expected structure');
  }
  
  // Sanitize
  const sanitized = sanitizeSVG(svgString);
  
  // Validate sanitized output
  if (!sanitized || sanitized.length === 0) {
    throw new Error('Sanitization resulted in empty SVG');
  }
  
  return sanitized;
}
