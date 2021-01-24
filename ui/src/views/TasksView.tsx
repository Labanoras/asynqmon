import React, { useEffect } from "react";
import { connect, ConnectedProps } from "react-redux";
import { makeStyles } from "@material-ui/core/styles";
import Container from "@material-ui/core/Container";
import Grid from "@material-ui/core/Grid";
import TasksTable from "../components/TasksTable";
import QueueInfoBanner from "../components/QueueInfoBanner";
import QueueBreadCrumb from "../components/QueueBreadcrumb";
import { useParams, useLocation } from "react-router-dom";
import { listQueuesAsync } from "../actions/queuesActions";
import { AppState } from "../store";

function mapStateToProps(state: AppState) {
  return {
    queues: state.queues.data.map((q) => q.name),
  };
}

const connector = connect(mapStateToProps, { listQueuesAsync });

const useStyles = makeStyles((theme) => ({
  container: {
    paddingTop: theme.spacing(2),
  },
  breadcrumbs: {
    marginBottom: theme.spacing(2),
  },
  banner: {
    marginBottom: theme.spacing(2),
  },
  tasksTable: {
    marginBottom: theme.spacing(4),
  },
}));

function useQuery(): URLSearchParams {
  return new URLSearchParams(useLocation().search);
}

interface RouteParams {
  qname: string;
}

const validStatus = ["active", "pending", "scheduled", "retry", "archived"];
const defaultStatus = "active";

function TasksView(props: ConnectedProps<typeof connector>) {
  const classes = useStyles();
  const { qname } = useParams<RouteParams>();
  const query = useQuery();
  let selected = query.get("status");
  if (!selected || !validStatus.includes(selected)) {
    selected = defaultStatus;
  }
  const { listQueuesAsync } = props;

  useEffect(() => {
    listQueuesAsync();
  }, [listQueuesAsync]);

  return (
    <Container maxWidth="lg">
      <Grid container spacing={0} className={classes.container}>
        <Grid xs={12} className={classes.breadcrumbs}>
          <QueueBreadCrumb queues={props.queues} selectedQueue={qname} />
        </Grid>
        <Grid item xs={12} className={classes.banner}>
          <QueueInfoBanner qname={qname} />
        </Grid>
        <Grid item xs={12} className={classes.tasksTable}>
          <TasksTable queue={qname} selected={selected} />
        </Grid>
      </Grid>
    </Container>
  );
}

export default connector(TasksView);
