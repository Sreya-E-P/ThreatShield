// frontend/src/components/ThreatMap.jsx (Enhanced)
import React, { useEffect, useRef, useState } from 'react';
import { Box, Typography, CircularProgress, Tooltip } from '@mui/material';
import * as d3 from 'd3';
import { geoPath, geoMercator } from 'd3-geo';
import { feature } from 'topojson-client';

const ThreatMap = ({ threats = [], height = 400, onCountryClick }) => {
  const svgRef = useRef();
  const containerRef = useRef();
  const [mapData, setMapData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [dimensions, setDimensions] = useState({ width: 800, height });
  const [selectedCountry, setSelectedCountry] = useState(null);

  // Country coordinates for threat display
  const countryCoordinates = {
    'United States': { lat: 37.0902, lon: -95.7129 },
    'China': { lat: 35.8617, lon: 104.1954 },
    'Russia': { lat: 61.5240, lon: 105.3188 },
    'India': { lat: 20.5937, lon: 78.9629 },
    'United Kingdom': { lat: 51.5074, lon: -0.1278 },
    'Germany': { lat: 51.1657, lon: 10.4515 },
    'France': { lat: 46.2276, lon: 2.2137 },
    'Brazil': { lat: -14.2350, lon: -51.9253 },
    'Australia': { lat: -25.2744, lon: 133.7751 },
    'Japan': { lat: 36.2048, lon: 138.2529 },
    'South Korea': { lat: 35.9078, lon: 127.7669 },
    'Ukraine': { lat: 48.3794, lon: 31.1656 },
    'Iran': { lat: 32.4279, lon: 53.6880 },
    'North Korea': { lat: 40.3399, lon: 127.5101 },
  };

  useEffect(() => {
    // Load world map data
    fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json')
      .then(response => response.json())
      .then(worldData => {
        const countries = feature(worldData, worldData.objects.countries);
        setMapData(countries);
        setLoading(false);
      })
      .catch(error => {
        console.error('Failed to load map data:', error);
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    if (!svgRef.current || !mapData) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = dimensions.width;
    const height = dimensions.height;

    // Create projection
    const projection = geoMercator()
      .fitSize([width, height], mapData);

    const path = geoPath().projection(projection);

    // Count threats by country
    const countryCounts = {};
    const threatDetails = {};

    threats.forEach(threat => {
      let country = threat.country || 'Unknown';
      
      // Try to infer country from IP if available
      if (country === 'Unknown' && threat.indicators) {
        // Simple country detection logic (in production, use GeoIP)
        const ip = threat.indicators.find(i => i.type === 'ip')?.value;
        if (ip) {
          // Use a simple mapping for demo
          if (ip.startsWith('185.')) country = 'Russia';
          else if (ip.startsWith('45.')) country = 'China';
          else if (ip.startsWith('103.')) country = 'India';
          else if (ip.startsWith('104.')) country = 'United States';
        }
      }
      
      countryCounts[country] = (countryCounts[country] || 0) + 1;
      
      if (!threatDetails[country]) {
        threatDetails[country] = [];
      }
      threatDetails[country].push({
        type: threat.type,
        severity: threat.severity,
        risk_score: threat.risk_score
      });
    });

    // Create color scale
    const maxCount = Math.max(...Object.values(countryCounts), 1);
    const colorScale = d3.scaleSequential(d3.interpolateReds)
      .domain([0, maxCount]);

    // Draw map
    svg.selectAll('.country')
      .data(mapData.features)
      .enter()
      .append('path')
      .attr('class', 'country')
      .attr('d', path)
      .attr('fill', d => {
        const countryName = d.properties?.name;
        const count = countryCounts[countryName] || 0;
        if (count === 0) return '#2a2a2a';
        return colorScale(count);
      })
      .attr('stroke', '#fff')
      .attr('stroke-width', 0.5)
      .style('cursor', 'pointer')
      .style('transition', 'all 0.2s')
      .on('mouseover', function(event, d) {
        const countryName = d.properties?.name;
        const count = countryCounts[countryName] || 0;
        
        d3.select(this)
          .attr('stroke', '#ff9800')
          .attr('stroke-width', 2);
        
        // Show tooltip
        const tooltip = svg.append('g')
          .attr('class', 'tooltip')
          .attr('transform', `translate(${event.offsetX + 15},${event.offsetY - 15})`);
        
        tooltip.append('rect')
          .attr('width', 180)
          .attr('height', 70)
          .attr('fill', '#1e1e2f')
          .attr('stroke', '#ff9800')
          .attr('rx', 6)
          .attr('ry', 6);
        
        tooltip.append('text')
          .attr('x', 10)
          .attr('y', 20)
          .text(countryName)
          .style('fill', 'white')
          .style('font-weight', 'bold')
          .style('font-size', '12px');
        
        tooltip.append('text')
          .attr('x', 10)
          .attr('y', 40)
          .text(`Threats: ${count}`)
          .style('fill', '#ff9800')
          .style('font-size', '11px');
        
        if (threatDetails[countryName]?.length) {
          const avgRisk = threatDetails[countryName].reduce((s, t) => s + (t.risk_score || 0.5), 0) / threatDetails[countryName].length;
          tooltip.append('text')
            .attr('x', 10)
            .attr('y', 55)
            .text(`Risk Score: ${(avgRisk * 100).toFixed(0)}%`)
            .style('fill', '#aaa')
            .style('font-size', '10px');
        }
      })
      .on('mouseout', function() {
        d3.select(this)
          .attr('stroke', '#fff')
          .attr('stroke-width', 0.5);
        
        svg.selectAll('.tooltip').remove();
      })
      .on('click', function(event, d) {
        const countryName = d.properties?.name;
        setSelectedCountry(countryName);
        if (onCountryClick) {
          onCountryClick(countryName, threatDetails[countryName] || []);
        }
      });

    // Add threat markers for high-risk areas
    const threatMarkers = [];
    Object.entries(threatDetails).forEach(([country, details]) => {
      const coords = countryCoordinates[country];
      if (coords && details.length > 2) {
        const [x, y] = projection([coords.lon, coords.lat]);
        if (x > 0 && x < width && y > 0 && y < height) {
          threatMarkers.push({ x, y, count: details.length, details });
        }
      }
    });

    // Add threat markers
    svg.selectAll('.threat-marker')
      .data(threatMarkers)
      .enter()
      .append('circle')
      .attr('cx', d => d.x)
      .attr('cy', d => d.y)
      .attr('r', d => 4 + Math.min(d.count, 10))
      .attr('fill', '#f44336')
      .attr('stroke', '#fff')
      .attr('stroke-width', 1)
      .style('cursor', 'pointer')
      .style('opacity', 0.8)
      .append('title')
      .text(d => `${d.count} active threats`);

    // Add legend
    const legend = svg.append('g')
      .attr('transform', `translate(${width - 150}, 20)`);

    legend.append('text')
      .attr('x', 0)
      .attr('y', 0)
      .text('Threat Density')
      .style('fill', 'white')
      .style('font-weight', 'bold')
      .style('font-size', '11px');

    const gradient = legend.append('defs')
      .append('linearGradient')
      .attr('id', 'threat-gradient')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '100%')
      .attr('y2', '0%');

    gradient.append('stop')
      .attr('offset', '0%')
      .attr('stop-color', '#4caf50');

    gradient.append('stop')
      .attr('offset', '50%')
      .attr('stop-color', '#ff9800');

    gradient.append('stop')
      .attr('offset', '100%')
      .attr('stop-color', '#f44336');

    legend.append('rect')
      .attr('x', 0)
      .attr('y', 20)
      .attr('width', 100)
      .attr('height', 10)
      .style('fill', 'url(#threat-gradient)');

    legend.append('text')
      .attr('x', 0)
      .attr('y', 40)
      .text('Low')
      .style('fill', 'white')
      .style('font-size', '9px');

    legend.append('text')
      .attr('x', 80)
      .attr('y', 40)
      .text('High')
      .style('fill', 'white')
      .style('font-size', '9px');

  }, [mapData, threats, dimensions, onCountryClick]);

  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height,
        });
      }
    };

    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, [height]);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box ref={containerRef} sx={{ width: '100%', height, position: 'relative' }}>
      {selectedCountry && (
        <Box
          sx={{
            position: 'absolute',
            top: 10,
            left: 10,
            zIndex: 10,
            bgcolor: 'background.paper',
            borderRadius: 1,
            p: 1,
            boxShadow: 2,
          }}
        >
          <Typography variant="caption" color="text.secondary">
            Selected: <strong>{selectedCountry}</strong>
          </Typography>
        </Box>
      )}
      <svg
        ref={svgRef}
        width={dimensions.width}
        height={dimensions.height}
        style={{ display: 'block', background: '#1a1a2e', borderRadius: 8 }}
      />
    </Box>
  );
};

export default ThreatMap;