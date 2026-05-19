import React, { useEffect, useRef } from "react";
import * as d3 from "d3";

function Graph({ data }) {
  const ref = useRef();

  useEffect(() => {
    const svg = d3.select(ref.current);
    svg.selectAll("*").remove();

    const width = 800;
    const height = 500;

    const nodes = {};
    const links = [];

    data.forEach((e) => {
      const device = e.device || "UNKNOWN";
      nodes[device] = { id: device };

      if (e.target) {
        nodes[e.target] = { id: e.target };
        links.push({ source: device, target: e.target });
      }
    });

    const nodeList = Object.values(nodes);

    const simulation = d3.forceSimulation(nodeList)
      .force("link", d3.forceLink(links).id(d => d.id).distance(120))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2));

    const link = svg.append("g")
      .selectAll("line")
      .data(links)
      .enter()
      .append("line")
      .style("stroke", "#555");

    const node = svg.append("g")
      .selectAll("circle")
      .data(nodeList)
      .enter()
      .append("circle")
      .attr("r", 10)
      .style("fill", "#22c55e")
      .call(d3.drag()
        .on("start", dragstart)
        .on("drag", drag)
        .on("end", dragend)
      );

    const label = svg.append("g")
      .selectAll("text")
      .data(nodeList)
      .enter()
      .append("text")
      .text(d => d.id)
      .style("fill", "white");

    simulation.on("tick", () => {
      link
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);

      node
        .attr("cx", d => d.x)
        .attr("cy", d => d.y);

      label
        .attr("x", d => d.x + 10)
        .attr("y", d => d.y);
    });

    function dragstart(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function drag(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragend(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

  }, [data]);

  return <svg ref={ref} width={800} height={500} />;
}

export default Graph;