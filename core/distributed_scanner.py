from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import threading
import queue
import time
import uuid
from abc import ABC, abstractmethod
import json


class ScanNodeStatus(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    BUSY = "busy"
    FAILED = "failed"
    OFFLINE = "offline"
    RECOVERING = "recovering"


class TaskStatus(Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"


class LoadBalancingStrategy(Enum):
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    PERFORMANCE_BASED = "performance_based"
    RANDOM = "random"
    ADAPTIVE = "adaptive"


@dataclass
class ScanNode:
    node_id: str
    hostname: str
    port: int
    status: ScanNodeStatus = ScanNodeStatus.IDLE
    active_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    total_capacity: int = 10
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    network_latency: float = 0.0
    last_heartbeat: float = field(default_factory=time.time)
    performance_score: float = 100.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_healthy(self) -> bool:
        return self.status != ScanNodeStatus.FAILED and \
               time.time() - self.last_heartbeat < 30
    
    def get_available_capacity(self) -> int:
        return max(0, self.total_capacity - self.active_tasks)
    
    def get_utilization(self) -> float:
        return (self.active_tasks / self.total_capacity) * 100
    
    def update_heartbeat(self):
        self.last_heartbeat = time.time()


@dataclass
class DistributedTask:
    task_id: str
    scan_type: str
    target_url: str
    payload: str
    parameter: str
    status: TaskStatus = TaskStatus.PENDING
    assigned_node: Optional[str] = None
    result: Optional[Dict] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 3
    priority: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_duration(self) -> Optional[float]:
        if self.completed_at is None or self.started_at is None:
            return None
        return self.completed_at - self.started_at
    
    def is_retryable(self) -> bool:
        return self.retry_count < self.max_retries and self.status == TaskStatus.FAILED
    
    def mark_started(self):
        self.started_at = time.time()
        self.status = TaskStatus.RUNNING
    
    def mark_completed(self, result: Dict):
        self.completed_at = time.time()
        self.result = result
        self.status = TaskStatus.COMPLETED
    
    def mark_failed(self, error: str):
        self.completed_at = time.time()
        self.error = error
        self.status = TaskStatus.FAILED
        self.retry_count += 1


class LoadBalancer:
    def __init__(self, strategy: LoadBalancingStrategy = LoadBalancingStrategy.ADAPTIVE):
        self.strategy = strategy
        self.round_robin_index = 0
        self.lock = threading.Lock()
    
    def select_node(self, nodes: Dict[str, ScanNode]) -> Optional[str]:
        healthy_nodes = {nid: node for nid, node in nodes.items() if node.is_healthy()}
        
        if not healthy_nodes:
            return None
        
        if self.strategy == LoadBalancingStrategy.ROUND_ROBIN:
            return self._round_robin(healthy_nodes)
        elif self.strategy == LoadBalancingStrategy.LEAST_LOADED:
            return self._least_loaded(healthy_nodes)
        elif self.strategy == LoadBalancingStrategy.PERFORMANCE_BASED:
            return self._performance_based(healthy_nodes)
        elif self.strategy == LoadBalancingStrategy.RANDOM:
            return self._random(healthy_nodes)
        elif self.strategy == LoadBalancingStrategy.ADAPTIVE:
            return self._adaptive(healthy_nodes)
        
        return self._least_loaded(healthy_nodes)
    
    def _round_robin(self, nodes: Dict[str, ScanNode]) -> Optional[str]:
        with self.lock:
            node_ids = list(nodes.keys())
            if not node_ids:
                return None
            
            selected = node_ids[self.round_robin_index % len(node_ids)]
            self.round_robin_index += 1
            return selected
    
    def _least_loaded(self, nodes: Dict[str, ScanNode]) -> Optional[str]:
        candidates = [(nid, node) for nid, node in nodes.items() 
                     if node.get_available_capacity() > 0]
        
        if not candidates:
            return None
        
        return min(candidates, key=lambda x: x[1].get_utilization())[0]
    
    def _performance_based(self, nodes: Dict[str, ScanNode]) -> Optional[str]:
        candidates = [(nid, node) for nid, node in nodes.items() 
                     if node.get_available_capacity() > 0]
        
        if not candidates:
            return None
        
        scores = []
        for nid, node in candidates:
            score = node.performance_score * (1 - node.cpu_usage / 100.0)
            scores.append((nid, score))
        
        return max(scores, key=lambda x: x[1])[0]
    
    def _random(self, nodes: Dict[str, ScanNode]) -> Optional[str]:
        import random
        candidates = [nid for nid, node in nodes.items() 
                     if node.get_available_capacity() > 0]
        
        return random.choice(candidates) if candidates else None
    
    def _adaptive(self, nodes: Dict[str, ScanNode]) -> Optional[str]:
        candidates = [(nid, node) for nid, node in nodes.items() 
                     if node.get_available_capacity() > 0]
        
        if not candidates:
            return None
        
        scores = []
        for nid, node in candidates:
            utilization_factor = 1 - (node.get_utilization() / 100.0)
            performance_factor = node.performance_score / 100.0
            latency_factor = 1 / (1 + node.network_latency)
            
            combined_score = (utilization_factor * 0.4 + 
                            performance_factor * 0.4 + 
                            latency_factor * 0.2)
            
            scores.append((nid, combined_score))
        
        return max(scores, key=lambda x: x[1])[0]


class TaskScheduler:
    def __init__(self):
        self.task_queue: queue.PriorityQueue = queue.PriorityQueue()
        self.tasks: Dict[str, DistributedTask] = {}
        self.lock = threading.Lock()
    
    def submit_task(self, task: DistributedTask):
        with self.lock:
            self.tasks[task.task_id] = task
            self.task_queue.put((-task.priority, task.task_id))
    
    def get_next_task(self, timeout: float = 1.0) -> Optional[DistributedTask]:
        try:
            _, task_id = self.task_queue.get(timeout=timeout)
            with self.lock:
                return self.tasks.get(task_id)
        except queue.Empty:
            return None
    
    def get_task(self, task_id: str) -> Optional[DistributedTask]:
        with self.lock:
            return self.tasks.get(task_id)
    
    def update_task(self, task: DistributedTask):
        with self.lock:
            self.tasks[task.task_id] = task
    
    def get_pending_tasks(self) -> List[DistributedTask]:
        with self.lock:
            return [t for t in self.tasks.values() 
                   if t.status == TaskStatus.PENDING]
    
    def get_failed_tasks(self) -> List[DistributedTask]:
        with self.lock:
            return [t for t in self.tasks.values() 
                   if t.status == TaskStatus.FAILED and t.is_retryable()]
    
    def get_task_statistics(self) -> Dict[str, int]:
        with self.lock:
            stats = defaultdict(int)
            for task in self.tasks.values():
                stats[task.status.value] += 1
            return dict(stats)


class NodeHealthMonitor:
    def __init__(self, check_interval: int = 30):
        self.check_interval = check_interval
        self.monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self, nodes: Dict[str, ScanNode], callback: Callable):
        if self.monitoring:
            return
        
        self.monitoring = True
        
        def monitor_worker():
            while self.monitoring:
                time.sleep(self.check_interval)
                self._check_node_health(nodes, callback)
        
        self.monitor_thread = threading.Thread(daemon=True, target=monitor_worker)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _check_node_health(self, nodes: Dict[str, ScanNode], callback: Callable):
        for node_id, node in nodes.items():
            if not node.is_healthy():
                if node.status != ScanNodeStatus.OFFLINE:
                    node.status = ScanNodeStatus.OFFLINE
                    callback(node_id, ScanNodeStatus.OFFLINE)
            else:
                if node.status == ScanNodeStatus.OFFLINE:
                    node.status = ScanNodeStatus.RECOVERING
                    callback(node_id, ScanNodeStatus.RECOVERING)


class DistributedScanResults:
    def __init__(self):
        self.results: Dict[str, List[Dict]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def add_result(self, task_id: str, result: Dict):
        with self.lock:
            self.results[task_id].append(result)
    
    def add_results_batch(self, task_id: str, results: List[Dict]):
        with self.lock:
            self.results[task_id].extend(results)
    
    def get_results(self, task_id: str) -> List[Dict]:
        with self.lock:
            return self.results.get(task_id, []).copy()
    
    def get_all_results(self) -> Dict[str, List[Dict]]:
        with self.lock:
            return {k: v.copy() for k, v in self.results.items()}
    
    def aggregate_results(self) -> List[Dict]:
        with self.lock:
            all_results = []
            for results in self.results.values():
                all_results.extend(results)
            return all_results
    
    def clear(self):
        with self.lock:
            self.results.clear()


class DistributedScanner:
    def __init__(self, load_balancing: LoadBalancingStrategy = LoadBalancingStrategy.ADAPTIVE):
        self.nodes: Dict[str, ScanNode] = {}
        self.scheduler = TaskScheduler()
        self.load_balancer = LoadBalancer(load_balancing)
        self.health_monitor = NodeHealthMonitor()
        self.results = DistributedScanResults()
        
        self.lock = threading.RLock()
        self.scanning = False
        self.worker_threads = []
    
    def add_node(self, hostname: str, port: int, capacity: int = 10) -> str:
        node_id = str(uuid.uuid4())
        
        with self.lock:
            self.nodes[node_id] = ScanNode(
                node_id=node_id,
                hostname=hostname,
                port=port,
                total_capacity=capacity
            )
        
        return node_id
    
    def remove_node(self, node_id: str) -> bool:
        with self.lock:
            if node_id in self.nodes:
                del self.nodes[node_id]
                return True
        return False
    
    def get_node(self, node_id: str) -> Optional[ScanNode]:
        with self.lock:
            return self.nodes.get(node_id)
    
    def get_nodes(self) -> Dict[str, ScanNode]:
        with self.lock:
            return self.nodes.copy()
    
    def submit_scan_task(self, scan_type: str, target_url: str, payload: str,
                        parameter: str, priority: int = 0) -> str:
        task = DistributedTask(
            task_id=str(uuid.uuid4()),
            scan_type=scan_type,
            target_url=target_url,
            payload=payload,
            parameter=parameter,
            priority=priority
        )
        
        self.scheduler.submit_task(task)
        return task.task_id
    
    def assign_task_to_node(self, task: DistributedTask, node_id: str) -> bool:
        with self.lock:
            node = self.nodes.get(node_id)
            if not node or not node.is_healthy():
                return False
            
            if node.get_available_capacity() <= 0:
                return False
            
            task.assigned_node = node_id
            task.status = TaskStatus.ASSIGNED
            node.active_tasks += 1
            
            self.scheduler.update_task(task)
            return True
    
    def execute_task(self, task: DistributedTask) -> Optional[Dict]:
        node = self.get_node(task.assigned_node)
        if not node:
            return None
        
        try:
            task.mark_started()
            self.scheduler.update_task(task)
            
            result = self._simulate_task_execution(task)
            
            task.mark_completed(result)
            node.active_tasks -= 1
            node.completed_tasks += 1
            
            self.results.add_result(task.task_id, result)
            self.scheduler.update_task(task)
            
            return result
        
        except Exception as e:
            task.mark_failed(str(e))
            node.active_tasks -= 1
            node.failed_tasks += 1
            node.status = ScanNodeStatus.FAILED
            
            self.scheduler.update_task(task)
            return None
    
    def _simulate_task_execution(self, task: DistributedTask) -> Dict:
        time.sleep(0.1)
        return {
            'task_id': task.task_id,
            'scan_type': task.scan_type,
            'target_url': task.target_url,
            'parameter': task.parameter,
            'status': 'completed',
            'timestamp': time.time()
        }
    
    def start_distributed_scan(self, tasks: List[Tuple[str, str, str, str]], 
                              num_workers: int = 4):
        self.scanning = True
        self.health_monitor.start_monitoring(self.nodes, self._on_node_status_changed)
        
        for scan_type, target_url, payload, parameter in tasks:
            self.submit_scan_task(scan_type, target_url, payload, parameter)
        
        self.worker_threads = []
        for i in range(num_workers):
            thread = threading.Thread(
                target=self._worker_loop,
                name=f"ScanWorker-{i}",
                daemon=True
            )
            thread.start()
            self.worker_threads.append(thread)
    
    def _worker_loop(self):
        while self.scanning:
            task = self.scheduler.get_next_task(timeout=1.0)
            
            if not task:
                continue
            
            selected_node = self.load_balancer.select_node(self.nodes)
            if not selected_node:
                continue
            
            if not self.assign_task_to_node(task, selected_node):
                continue
            
            self.execute_task(task)
    
    def stop_distributed_scan(self):
        self.scanning = False
        self.health_monitor.stop_monitoring()
        
        for thread in self.worker_threads:
            thread.join(timeout=5)
        
        self.worker_threads.clear()
    
    def _on_node_status_changed(self, node_id: str, new_status: ScanNodeStatus):
        node = self.get_node(node_id)
        if node:
            node.status = new_status
    
    def get_node_statistics(self) -> Dict[str, Any]:
        with self.lock:
            stats = {
                'total_nodes': len(self.nodes),
                'healthy_nodes': sum(1 for n in self.nodes.values() if n.is_healthy()),
                'nodes': {}
            }
            
            for node_id, node in self.nodes.items():
                stats['nodes'][node_id] = {
                    'status': node.status.value,
                    'active_tasks': node.active_tasks,
                    'completed_tasks': node.completed_tasks,
                    'failed_tasks': node.failed_tasks,
                    'utilization': f"{node.get_utilization():.2f}%",
                    'performance_score': node.performance_score,
                    'cpu_usage': f"{node.cpu_usage:.2f}%",
                    'memory_usage': f"{node.memory_usage:.2f}%",
                }
            
            return stats
    
    def get_task_statistics(self) -> Dict[str, int]:
        return self.scheduler.get_task_statistics()
    
    def get_scan_results(self) -> List[Dict]:
        return self.results.aggregate_results()
    
    def get_detailed_results(self) -> Dict[str, List[Dict]]:
        return self.results.get_all_results()
    
    def retry_failed_tasks(self):
        failed_tasks = self.scheduler.get_failed_tasks()
        
        for task in failed_tasks:
            task.status = TaskStatus.PENDING
            self.scheduler.submit_task(task)
    
    def update_node_metrics(self, node_id: str, cpu_usage: float,
                           memory_usage: float, network_latency: float):
        node = self.get_node(node_id)
        if node:
            with self.lock:
                node.cpu_usage = cpu_usage
                node.memory_usage = memory_usage
                node.network_latency = network_latency
                node.performance_score = self._calculate_performance_score(node)
    
    def _calculate_performance_score(self, node: ScanNode) -> float:
        cpu_factor = (100 - node.cpu_usage) / 100
        memory_factor = (100 - node.memory_usage) / 100
        latency_factor = 1 / (1 + node.network_latency)
        
        return (cpu_factor * 0.4 + memory_factor * 0.4 + latency_factor * 0.2) * 100
    
    def get_scan_summary(self) -> Dict[str, Any]:
        return {
            'node_statistics': self.get_node_statistics(),
            'task_statistics': self.get_task_statistics(),
            'total_results': len(self.get_scan_results()),
            'scanning': self.scanning,
        }