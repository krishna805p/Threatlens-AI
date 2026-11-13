import React, { useEffect, useRef } from 'react';
import { Renderer, Camera, Transform, Texture, Program, Mesh, Plane } from 'ogl';

export const WarpText = ({
  text = 'THREATLENS AI',
  className = '',
  fontSize = 28,
  color = '#ffffff',
  warpFactor = 0.12,
}) => {
  const containerRef = useRef(null);
  const animFrameRef = useRef(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // 2D canvas for rendering high-res text texture
    const canvasText = document.createElement('canvas');
    const ctx = canvasText.getContext('2d');
    const width = 800;
    const height = 160;
    canvasText.width = width;
    canvasText.height = height;

    if (ctx) {
      ctx.clearRect(0, 0, width, height);
      ctx.font = `900 ${fontSize * 2}px font-mono, ui-monospace, monospace`;
      ctx.fillStyle = color;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.shadowColor = '#60a5fa';
      ctx.shadowBlur = 12;
      ctx.fillText(text, width / 2, height / 2);
    }

    let renderer;
    try {
      renderer = new Renderer({ alpha: true, antialias: true, dpr: Math.min(window.devicePixelRatio, 2) });
    } catch (e) {
      console.warn('WebGL initialization fallback for WarpText:', e);
      return;
    }

    const gl = renderer.gl;
    gl.clearColor(0, 0, 0, 0);

    const camera = new Camera(gl, { fov: 45 });
    camera.position.z = 2.4;

    const scene = new Transform();

    const texture = new Texture(gl, { generateMipmaps: false });
    texture.image = canvasText;

    const vertexShader = `
      attribute vec3 position;
      attribute vec2 uv;
      uniform mat4 modelViewMatrix;
      uniform mat4 projectionMatrix;
      uniform float uTime;
      uniform float uWarp;
      varying vec2 vUv;

      void main() {
        vUv = uv;
        vec3 pos = position;
        if (uWarp > 0.0) {
          pos.z += sin(pos.x * 3.5 + uTime * 2.2) * uWarp * 0.12;
          pos.y += cos(pos.x * 2.8 + uTime * 1.6) * uWarp * 0.06;
        }
        gl_Position = projectionMatrix * modelViewMatrix * vec4(pos, 1.0);
      }
    `;

    const fragmentShader = `
      precision highp float;
      uniform sampler2D tMap;
      varying vec2 vUv;

      void main() {
        vec4 color = texture2D(tMap, vUv);
        if (color.a < 0.02) discard;
        gl_FragColor = color;
      }
    `;

    const geometry = new Plane(gl, { width: 3.4, height: 0.68, widthSegments: 32, heightSegments: 16 });
    const program = new Program(gl, {
      vertex: vertexShader,
      fragment: fragmentShader,
      uniforms: {
        tMap: { value: texture },
        uTime: { value: 0 },
        uWarp: { value: prefersReducedMotion ? 0.0 : warpFactor },
      },
      transparent: true,
    });

    const mesh = new Mesh(gl, { geometry, program });
    mesh.setParent(scene);

    const glCanvas = gl.canvas;
    glCanvas.style.width = '100%';
    glCanvas.style.height = '100%';
    glCanvas.style.display = 'block';
    container.appendChild(glCanvas);

    const resize = () => {
      if (!container || !renderer) return;
      const rect = container.getBoundingClientRect();
      const w = rect.width || 300;
      const h = rect.height || 60;
      renderer.setSize(w, h);
      camera.perspective({ aspect: w / h });
    };

    resize();
    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(container);

    const startTime = performance.now();

    const update = (now) => {
      const elapsed = (now - startTime) * 0.001;
      program.uniforms.uTime.value = elapsed;
      renderer.render({ scene, camera });
      animFrameRef.current = requestAnimationFrame(update);
    };

    animFrameRef.current = requestAnimationFrame(update);

    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
      resizeObserver.disconnect();
      if (glCanvas && glCanvas.parentNode) {
        glCanvas.parentNode.removeChild(glCanvas);
      }
      const loseContext = gl.getExtension('WEBGL_lose_context');
      if (loseContext) loseContext.loseContext();
    };
  }, [text, fontSize, color, warpFactor]);

  return (
    <div className={`relative inline-block w-full max-w-lg h-16 overflow-hidden ${className}`}>
      <div ref={containerRef} className="w-full h-full flex items-center justify-center" />
      <span className="sr-only">{text}</span>
    </div>
  );
};

export default WarpText;
