// frontend/src/components/BlockchainGraph.jsx
import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import { Box, Typography } from '@mui/material';

const BlockchainGraph = ({ data }) => {
  const svgRef = useRef();
  const containerRef = useRef();

  useEffect(() => {
    if (!data || !svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = containerRef.current?.clientWidth || 600;
    const height = 350;

    svg.attr('width', width).attr('height', height);

    // Create sample blockchain data if none provided
    const nodes = data?.nodes || [
      { id: 'Wallet A', type: 'wallet', value: 1000 },
      { id: 'Wallet B', type: 'wallet', value: 500 },
      { id: 'Wallet C', type: 'wallet', value: 750 },
      { id: 'Exchange', type: 'exchange', value: 2000 },
      { id: 'Contract', type: 'contract', value: 300 },
      { id: 'Mixer', type: 'mixer', value: 1500 },
    ];

    const links = data?.links || [
      { source: 'Wallet A', target: 'Exchange', value: 100 },
      { source: 'Wallet B', target: 'Exchange', value: 50 },
      { source: 'Exchange', target: 'Wallet C', value: 75 },
      { source: 'Wallet C', target: 'Contract', value: 20 },
      { source: 'Contract', target: 'Mixer', value: 15 },
      { source: 'Mixer', target: 'Wallet A', value: 90 },
    ];

    // Create force simulation
    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(40));

    // Create links
    const link = svg.append('g')
      .selectAll('line')
      .data(links)
      .enter()
      .append('line')
      .attr('stroke', '#999')
      .attr('stroke-opacity', 0.6)
      .attr('stroke-width', d => Math.sqrt(d.value));

    // Create nodes
    const node = svg.append('g')
      .selectAll('circle')
      .data(nodes)
      .enter()
      .append('circle')
      .attr('r', d => Math.sqrt(d.value) / 2 + 10)
      .attr('fill', d => {
        switch(d.type) {
          case 'wallet': return '#2196f3';
          case 'exchange': return '#4caf50';
          case 'contract': return '#ff9800';
          case 'mixer': return '#f44336';
          default: return '#9c27b0';
        }
      })
      .attr('stroke', '#fff')
      .attr('stroke-width', 1.5)
      .call(d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended));

    // Add labels
    const label = svg.append('g')
      .selectAll('text')
      .data(nodes)
      .enter()
      .append('text')
      .text(d => d.id)
      .attr('font-size', '10px')
      .attr('dx', 15)
      .attr('dy', 4)
      .attr('fill', '#fff');

    // Add tooltips
    node.append('title')
      .text(d => `${d.id}\nType: ${d.type}\nValue: $${d.value}`);

    // Update positions on simulation tick
    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      node
        .attr('cx', d => d.x)
        .attr('cy', d => d.y);

      label
        .attr('x', d => d.x)
        .attr('y', d => d.y);
    });

    // Drag functions
    function dragstarted(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    // Legend
    const legend = svg.append('g')
      .attr('transform', `translate(${width - 150}, 20)`);

    const legendData = [
      { color: '#2196f3', label: 'Wallet' },
      { color: '#4caf50', label: 'Exchange' },
      { color: '#ff9800', label: 'Contract' },
      { color: '#f44336', label: 'Mixer' },
    ];

    legend.selectAll('rect')
      .data(legendData)
      .enter()
      .append('rect')
      .attr('x', 0)
      .attr('y', (d, i) => i * 20)
      .attr('width', 12)
      .attr('height', 12)
      .attr('fill', d => d.color);

    legend.selectAll('text')
      .data(legendData)
      .enter()
      .append('text')
      .attr('x', 20)
      .attr('y', (d, i) => i * 20 + 10)
      .text(d => d.label)
      .attr('font-size', '10px')
      .attr('fill', '#fff');

  }, [data]);

  return (
    <Box ref={containerRef} sx={{ width: '100%', height: '100%' }}>
      {data ? (
        <svg
          ref={svgRef}
          style={{ display: 'block', background: 'transparent' }}
        />
      ) : (
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
          <Typography color="text.secondary">No blockchain data available</Typography>
        </Box>
      )}
    </Box>
  );
};

export default BlockchainGraph;